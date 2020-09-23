
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.EnumUtils;
import org.python.jline.internal.Nullable;

import bil.*;
import term.*;
import symbol.ExternSymbol;
import serializer.Serializer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class PcodeExtractor extends GhidraScript {

    List<String> jumps = new ArrayList<String>() {{
        add("BRANCH");
        add("CBRANCH");
        add("BRANCHIND");
        add("CALL");
        add("CALLIND");
        add("CALLOTHER");
        add("RETURN");
    }};

    Term<Blk> returnBlk = null;
    Term<Program> program = null;
    FunctionManager funcMan;
    ghidra.program.model.listing.Program ghidraProgram;
    VarnodeContext context;

    Set<String> binOps = EnumUtils.getEnumMap(ExecutionType.BinOpType.class).keySet();
    Set<String> unOps = EnumUtils.getEnumMap(ExecutionType.UnOpType.class).keySet();
    Set<String> casts = EnumUtils.getEnumMap(ExecutionType.CastType.class).keySet();


    /**
     * Entry point to Ghidra Script. Calls serializer after processing of Terms.
     */
    @Override
    protected void run() throws Exception {
        ghidraProgram = currentProgram;
        funcMan = ghidraProgram.getFunctionManager();
        SimpleBlockModel simpleBM = new SimpleBlockModel(ghidraProgram);
        Listing listing = ghidraProgram.getListing();
        context = new VarnodeContext(ghidraProgram, ghidraProgram.getProgramContext(), ghidraProgram.getProgramContext());
        String cpuArch = getCpuArchitecture();

        program = createProgramTerm();
        Project project = createProject(cpuArch);
        program = iterateFunctions(simpleBM, listing);

        String jsonPath = getScriptArgs()[0];
        Serializer ser = new Serializer(project, jsonPath);
        ser.serializeProject();
        TimeUnit.SECONDS.sleep(3);

    }


    /**
     * @return: CPU architecture as string.
     * <p>
     * Uses Ghidra's language id to extract the CPU arch as "arch-bits" e.g. x86_64, x86_32 etc.
     */
    protected String getCpuArchitecture() {
        String langId = ghidraProgram.getCompilerSpec().getLanguage().getLanguageID().getIdAsString();
        String[] arch = langId.split(":");
        return arch[0] + "_" + arch[2];
    }


    /**
     * @param simpleBM: Simple Block Model to iterate over blocks
     * @param listing:  Listing to get assembly instructions
     * @return: Processed Program Term
     * <p>
     * Iterates over functions to create sub terms and calls the block iterator to add all block terms to each subroutine.
     */
    protected Term<Program> iterateFunctions(SimpleBlockModel simpleBM, Listing listing) {
        FunctionIterator functions = funcMan.getFunctionsNoStubs(true);
        for (Function func : functions) {
            if (!func.isThunk()) {
                Term<Sub> currentSub = createSubTerm(func);
                currentSub.getTerm().setBlocks(iterateBlocks(currentSub, simpleBM, listing));
                program.getTerm().addSub(currentSub);
            }
        }

        return program;
    }


    /**
     * @param currentSub: Current Sub Term to processed
     * @param simpleBM:   Simple Block Model to iterate over blocks
     * @param listing:    Listing to get assembly instructions
     * @return: new ArrayList of Blk Terms
     * <p>
     * Iterates over all blocks and calls the instruction iterator to add def and jmp terms to each block.
     */
    protected ArrayList<Term<Blk>> iterateBlocks(Term<Sub> currentSub, SimpleBlockModel simpleBM, Listing listing) {
        ArrayList<Term<Blk>> blocks = new ArrayList<Term<Blk>>();
        try {
            CodeBlockIterator blockIter = simpleBM.getCodeBlocksContaining(currentSub.getTerm().getAddresses(), getMonitor());
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blocks.addAll(iterateInstructions(createBlkTerm(block), listing, block));
            }
        } catch (CancelledException e) {
            System.out.printf("Could not retrieve all basic blocks comprised by function: %s\n", currentSub.getTerm().getName());
        }

        return blocks;
    }


    /**
     * @param block:     Blk Term to be filled with instructions
     * @param listing:   Assembly instructions
     * @param codeBlock: codeBlock for retrieving its instructions
     * @return: new Blk Term
     * <p>
     * Iterates over pcode instructions and adds either jmp or def term depending on the mnemonic.
     */
    protected ArrayList<Term<Blk>> iterateInstructions(Term<Blk> block, Listing listing, CodeBlock codeBlock) {
        int instrCount = 0;
        int pCodeIndex = 0;
        InstructionIterator instructions = listing.getInstructions(codeBlock, true);
        long numOfInstr = StreamSupport.stream(listing.getInstructions(codeBlock, true).spliterator(), false).count();
        ArrayList<Term<Blk>> blocks = new ArrayList<Term<Blk>>();
        blocks.add(block);
        for (Instruction instr : instructions) {
            int numOfPcode = instr.getPcode(true).length;
            blocks = iteratePcode(blocks, instr, instrCount, pCodeIndex, numOfInstr, numOfPcode);
            instrCount++;
            pCodeIndex += numOfPcode;
        }

        if (blocks.get(0).getTerm().getDefs().isEmpty() && blocks.get(0).getTerm().getJmps().isEmpty()) {
            blocks.get(0).getTerm().addJmp(handleEmptyBlock(codeBlock));
        }

        return blocks;
    }


    /**
     * @param codeBlock: Current empty block
     * @return New jmp term containing fall through address
     */
    protected Term<Jmp> handleEmptyBlock(CodeBlock codeBlock) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s", codeBlock.getFirstStartAddress().toString(), 0), codeBlock.getFirstStartAddress().toString());
        Tid gotoTid = new Tid();
        try {
            CodeBlockReferenceIterator destinations = codeBlock.getDestinations(getMonitor());
            while (destinations.hasNext()) {
                String destAddr = destinations.next().getDestinationBlock().getFirstStartAddress().toString();
                gotoTid.setId(String.format("blk_%s", destAddr));
                gotoTid.setAddress(destAddr);
                break;
            }
        } catch (CancelledException e) {
            System.out.printf("Could not retrieve destinations for block at: %s\n", codeBlock.getFirstStartAddress().toString());
        }
        return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid)));
    }


    /**
     * @param instr:      Instruction to extract Pcode from
     * @param instrCount: The number of instructions of the current block
     * @param pCodeIndex: Index of the current pcode instruction
     * @param numOfInstr: Number of instructions of the current block
     * @param numOfPcode: Total number of pcode instructions to identify defs at the end
     * @return: current block
     * <p>
     * Iterates over each Pcode instruction of the current assembly Instruction
     * and creates the corresponding jmp or def term.
     */
    protected ArrayList<Term<Blk>> iteratePcode(ArrayList<Term<Blk>> blocks, Instruction instr, int instrCount, int pCodeIndex, long numOfInstr, int numOfPcode) {
        int pCodeIteration = 0;
        Term<Blk> retBlk = null;
        Term<Blk> block = blocks.get(0);
        for (PcodeOp pcodeOp : instr.getPcode(true)) {
            String mnemonic = pcodeOp.getMnemonic();
            if (this.jumps.contains(mnemonic)) {
                // If we return a 0 constant, we create a separate basic block for this return instruction
                // We also set the return address of the preceding call to the address of the return block
                if (mnemonic.equals("RETURN") && pcodeOp.getInput(0).getOffset() == 0) {
                    retBlk = createReturnBlock(mnemonic, pcodeOp, block.getTid().getAddress());
                    Label retLab = new Label(retBlk.getTid());
                    block.getTerm().getJmps().get(block.getTerm().getJmps().size() - 1).getTerm().getCall().setReturn_(retLab);
                } else {
                    Term<Jmp> jmp = createJmpTerm(instr, pCodeIndex, pcodeOp, mnemonic, instr.getAddress());
                    block.getTerm().addJmp(jmp);
                }
            } else {
                // The last pcode instruction of the last assembly instruction of a basic block should always be a jmp
                // If not cast the last instruction to a jump using the fallthrough address as destination
                if (instrCount == numOfInstr - 1 && pCodeIteration == numOfPcode - 1) {
                    block.getTerm().addJmp(castToJmp(instr, pCodeIndex));
                } else {
                    Term<Def> def = createDefTerm(pCodeIndex, pcodeOp, instr.getAddress());
                    block.getTerm().addDef(def);
                }
            }
            pCodeIteration++;
            pCodeIndex++;
        }

        if (retBlk != null) {
            blocks.add(retBlk);
        }

        return blocks;
    }


    /**
     * @param instr:      last instruction of the Block
     * @param pCodeCount: index of the last pcode instruction
     * @return: Jmp term casted from def using the BRANCH type and fall through address
     * <p>
     * If the last pcode instruction of a block is a definition, cast it into a Jmp
     * with the fall through address as goto label
     */
    protected Term<Jmp> castToJmp(Instruction instr, int pCodeCount) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s", instr.getAddress().toString(), pCodeCount), instr.getAddress().toString());
        Tid gotoTid = new Tid(String.format("blk_%s", instr.getFallThrough().toString()), instr.getFallThrough().toString());
        return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid)));
    }


    /**
     * @param cpuArch: CPU architecture as string
     * @return: new Project
     * <p>
     * Creates the project object and adds the stack pointer register and program term.
     */
    protected Project createProject(String cpuArch) {
        Project project = new Project();
        CompilerSpec comSpec = currentProgram.getCompilerSpec();
        Register stackPointerRegister = comSpec.getStackPointer();
        Variable stackPointerVar = new Variable(stackPointerRegister.getName(), stackPointerRegister.getBitLength(), false);
        project.setProgram(program);
        project.setStackPointerRegister(stackPointerVar);
        project.setCpuArch(cpuArch);

        return project;
    }


    /**
     * @return: new Program Term
     * <p>
     * Creates the project term with an unique TID and adds external symbols.
     */
    protected Term<Program> createProgramTerm() {
        Tid progTid = new Tid(String.format("prog_%s", ghidraProgram.getMinAddress().toString()), ghidraProgram.getMinAddress().toString());
        ArrayList<ExternSymbol> externalSymbols = new ArrayList<ExternSymbol>();
        SymbolTable symTab = ghidraProgram.getSymbolTable();
        AddressIterator entryPoints = symTab.getExternalEntryPointIterator();
        ArrayList<Tid> entryTids = new ArrayList<Tid>();
        while (entryPoints.hasNext()) {
            Address entry = entryPoints.next();
            entryTids.add(new Tid(String.format("sub_%s", entry.toString()), entry.toString()));
        }
        SymbolIterator symExtern = symTab.getExternalSymbols();
        while (symExtern.hasNext()) {
            Symbol ex = symExtern.next();
            externalSymbols.add(createExternSymbol(ex));
        }
        return new Term<Program>(progTid, new Program(new ArrayList<Term<Sub>>(), externalSymbols, entryTids));
    }


    /**
     * @param symbol:  External symbol
     * @return: new ExternSymbol
     * <p>
     * Creates an external symbol with an unique TID, a calling convention and argument objects.
     */
    protected ExternSymbol createExternSymbol(Symbol symbol) {
        Symbol libSym = getInternalCaller(symbol);
        Tid tid = new Tid(String.format("sub_%s", libSym.getAddress().toString()), libSym.getAddress().toString());
        ArrayList<Arg> args = createArguments(libSym);
        Boolean noReturn = hasVoidReturn(funcMan.getFunctionAt(libSym.getAddress()));
        return new ExternSymbol(tid, libSym.getAddress().toString(), libSym.getName(), funcMan.getDefaultCallingConvention().getName(), args, noReturn);

    }


    /**
     * @param symbol:  External symbol
     * @return: internally called symbol for external symbol
     * <p>
     * Gets the internally called Thunk Function for an external symbol.
     */
    protected Symbol getInternalCaller(Symbol symbol) {
        SymbolIterator symDefined = ghidraProgram.getSymbolTable().getDefinedSymbols();
        Symbol candidate = symbol;
        while (symDefined.hasNext()) {
            Symbol def = symDefined.next();
            if (def.getName().equals(symbol.getName()) && !def.isExternal()) {
                if (!isThunkFunctionRef(def)) {
                    candidate = def;
                }
            }
        }
        return candidate;
    }


    /**
     * @param def:     Defined symbol
     * @return: true if referencing function is thunk, else false
     * <p>
     * Checks if current external symbol is referenced by a Thunk Function.
     * If so, the Thunk Function is the internally called function.
     */
    protected Boolean isThunkFunctionRef(Symbol def) {
        Address refAddr = def.getReferences()[0].getFromAddress();
        return funcMan.getFunctionContaining(refAddr) != null && funcMan.getFunctionContaining(refAddr).isThunk();
    }


    protected Boolean hasVoidReturn(Function func) {
        return func.hasNoReturn() || func.getReturn().getDataType().getName().equals("void");
    }


    /**
     * @param symbol:  Symbol used to get corresponding function
     * @return: new Arg ArrayList
     * <p>
     * Creates Arguments for the ExternSymbol object.
     */
    protected ArrayList<Arg> createArguments(Symbol symbol) {
        ArrayList<Arg> args = new ArrayList<Arg>();
        Function func = funcMan.getFunctionAt(symbol.getAddress());
        Parameter[] params = func.getParameters();
        for (Parameter param : params) {
            args.add(specifyArg(param));
        }
        if (!hasVoidReturn(func)) {
            args.add(new Arg(createVariable(func.getReturn().getFirstStorageVarnode()), "OUTPUT"));
        }

        return args;
    }


    /**
     * @param param: Function parameter
     * @return: new Arg
     * <p>
     * Specifies if the argument is a stack variable or a register.
     */
    protected Arg specifyArg(Parameter param) {
        Arg arg = new Arg();
        if (param.isStackVariable()) {
            Variable stackVar = createVariable(param.getFirstStorageVarnode());
            arg.setLocation(new Expression("LOAD", stackVar));
            arg.setIntent("INPUT");
        } else if (param.isRegisterVariable()) {
            arg.setVar(createVariable(param.getFirstStorageVarnode()));
            arg.setIntent("INPUT");
        }

        return arg;
    }


    /**
     * @param func: Ghidra function object
     * @return: new Sub Term
     * <p>
     * Creates a Sub Term with an unique TID consisting of the prefix sub and its entry address.
     */
    protected Term<Sub> createSubTerm(Function func) {
        Tid subTid = new Tid(String.format("sub_%s", func.getEntryPoint().toString()), func.getEntryPoint().toString());
        return new Term<Sub>(subTid, new Sub(func.getName(), func.getBody()));
    }


    /**
     * @param block: Instruction block
     * @return: new Blk Term
     * <p>
     * Creates a Blk Term with an unique TID consisting of the prefix blk and its entry address.
     */
    protected Term<Blk> createBlkTerm(CodeBlock block) {
        Tid blkTid = new Tid(String.format("blk_%s", block.getFirstStartAddress().toString()), block.getFirstStartAddress().toString());
        return new Term<Blk>(blkTid, new Blk(new ArrayList<Term<Def>>(), new ArrayList<Term<Jmp>>()));
    }


    protected Term<Blk> createReturnBlock(String mnemonic, PcodeOp op, String address) {
        Tid blkTid = new Tid(String.format("blk_%s_r", address), address);
        Tid jmpTid = new Tid(String.format("instr_%s_%s_r", address, 0), address);
        Term<Jmp> ret = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(mnemonic, op, null)));
        ArrayList<Term<Jmp>> jmps = new ArrayList<Term<Jmp>>() {{
            add(ret);
        }};
        return new Term<Blk>(blkTid, new Blk(new ArrayList<Term<Def>>(), jmps));
    }


    /**
     * @param instr:      Assembly instruction
     * @param pCodeCount: Pcode index in current block
     * @param pcodeOp:    Pcode instruction
     * @param mnemonic:   Pcode instruction mnemonic
     * @param instrAddr:  Assembly instruction address
     * @return: new Jmp Term
     * <p>
     * Creates a Jmp Term with an unique TID consisting of the prefix jmp, its instruction address and the index of the pcode in the block.
     * Depending on the instruction, it either has a goto label, a goto label and a condition or a call object.
     */
    protected Term<Jmp> createJmpTerm(Instruction instr, int pCodeCount, PcodeOp pcodeOp, String mnemonic, Address instrAddr) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pCodeCount), instrAddr.toString());
        if (mnemonic.equals("CBRANCH")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), createVariable(pcodeOp.getInput(1))));
        } else if (mnemonic.equals("BRANCH") || mnemonic.equals("BRANCHIND")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null)));
        } else if (mnemonic.equals("RETURN")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(mnemonic, pcodeOp, null)));
        }

        Term<Jmp> call = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, mnemonic, createCall(instr, mnemonic, pcodeOp)));
        call = checkIfCallindResolved(call);

        return call;
    }


    protected Term<Jmp> checkIfCallindResolved(Term<Jmp> call) {
        if (call.getTerm().getMnemonic().equals("CALLIND")) {
            if (call.getTerm().getCall().getTarget().getIndirect() == null) {
                call.getTerm().setMnemonic("CALL");
            }
        }

        return call;
    }


    /**
     * @param pCodeCount: Pcode index in current block
     * @param pcodeOp:    Pcode instruction
     * @param instrAddr:  Assembly instruction address
     * @return: new Def Term
     * <p>
     * Creates a Def Term with an unique TID consisting of the prefix def, its instruction address and the index of the pcode in the block.
     */
    protected Term<Def> createDefTerm(int pCodeCount, PcodeOp pcodeOp, Address instrAddr) {
        Tid defTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pCodeCount), instrAddr.toString());
        if (pcodeOp.getMnemonic().equals("STORE")) {
            return new Term<Def>(defTid, new Def(createExpression(pcodeOp)));
            // cast copy instructions that have address outputs into store instructions
        } else if (pcodeOp.getMnemonic().equals("COPY") && pcodeOp.getOutput().isAddress()) {
            return new Term<Def>(defTid, new Def(new Expression("STORE", createVariable(pcodeOp.getOutput()), createVariable(pcodeOp.getInput(0)))));
        }
        return new Term<Def>(defTid, new Def(createVariable(pcodeOp.getOutput()), createExpression(pcodeOp)));
    }


    /**
     * @param node: Varnode source for Variable
     * @return: new Variable
     * <p>
     * Set register name based on being a register, virtual register, constant or ram address.
     * In case it is a virtual register, prefix the name with $U.
     * In case it is a constant, remove the const prefix from the constant.
     */
    protected Variable createVariable(Varnode node) {
        Variable var = new Variable();
        if (node.isRegister()) {
            var.setName(getRegisterMnemonic(node));
            var.setIsVirtual(false);
        } else if (node.isUnique()) {
            var.setName(renameVirtualRegister(node.getAddress().toString()));
            var.setIsVirtual(true);
        } else if (node.isConstant()) {
            var.setValue(removeConstantPrefix(node.getAddress().toString()));
            var.setIsVirtual(false);
        } else if (node.isAddress()) {
            var.setAddress(node.getAddress().toString());
            var.setIsVirtual(false);
        } else if (node.isFree()) {
            var.setAddress(removeStackPrefix(node.getAddress().toString()));
            var.setIsVirtual(false);
        }

        var.setSize(node.getSize());

        return var;
    }


    /**
     * @param pcodeOp: Pcode instruction
     * @return: new Epxression
     * <p>
     * Create an Expression using the input varnodes of the pcode instruction.
     */
    protected Expression createExpression(PcodeOp pcodeOp) {
        String mnemonic = pcodeOp.getMnemonic();
        List<Variable> in = new ArrayList<Variable>();

        for (Varnode input : pcodeOp.getInputs()) {
            in.add(createVariable(input));
        }

        int inputLen = in.size();

        if (inputLen == 1) {
            return new Expression(mnemonic, in.get(0));
        } else if (inputLen == 2) {
            return new Expression(mnemonic, in.get(0), in.get(1));
        } else {
            return new Expression(mnemonic, in.get(0), in.get(1), in.get(2));
        }
    }


    /**
     * @param mnemonic:    Pcode instruction mnemonic
     * @param pcodeOp:     Pcode instruction
     * @param fallThrough: fallThrough address of branch/call
     * @return: new Label
     * <p>
     * Create a Label based on the branch instruction. For indirect branches and calls, it consists of a Variable, for calls of a sub TID
     * and for branches of a blk TID.
     */
    protected Label createLabel(String mnemonic, PcodeOp pcodeOp, @Nullable Address fallThrough) {
        if (fallThrough == null) {
            if (mnemonic.equals("CALLIND")) {
                Tid subTid = getTargetTid(pcodeOp.getInput(0));
                if (subTid != null) {
                    return new Label(subTid);
                } else {
                    return new Label((Variable) createVariable(pcodeOp.getInput(0)));
                }
            }

            if (mnemonic.equals("BRANCHIND") || mnemonic.equals("RETURN")) {
                return new Label((Variable) createVariable(pcodeOp.getInput(0)));
            }

            if (mnemonic.equals("CALL") || mnemonic.equals("CALLOTHER")) {
                return new Label((Tid) new Tid(String.format("sub_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
            }

            if (mnemonic.equals("BRANCH") || mnemonic.equals("CBRANCH")) {
                return new Label((Tid) new Tid(String.format("blk_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
            }
        }

        return new Label((Tid) new Tid(String.format("blk_%s", fallThrough.toString()), fallThrough.toString()));
    }


    protected Tid getTargetTid(Varnode target) {
        if (!target.isRegister() && !target.isUnique()) {
            Reference[] referenced = ghidraProgram.getReferenceManager().getReferencesFrom(target.getAddress());
            if(referenced.length != 0) {
                for (ExternSymbol symbol : program.getTerm().getExternSymbols()) {
                    if (symbol.getAddress().equals(referenced[0].getToAddress().toString())) {
                        return symbol.getTid();
                    }
                }
            }
        }
        return null;
    }


    /**
     * @param instr:    Assembly instruction
     * @param mnemonic: Pcode instruction mnemonic
     * @param pcodeOp:  Pcode instruction
     * @return: new Call
     * <p>
     * Creates a Call object, using a target and return Label.
     */
    protected Call createCall(Instruction instr, String mnemonic, PcodeOp pcodeOp) {
        return new Call(createLabel(mnemonic, pcodeOp, null), createLabel(mnemonic, pcodeOp, instr.getFallThrough()));
    }


    /**
     * @param address: Virtual register address
     * @return: Prefixed virtual register naem
     * <p>
     * Prefixes virtual register with $U.
     */
    protected String renameVirtualRegister(String address) {
        return "$U" + address.replaceFirst("^(unique:0+(?!$))", "");
    }


    /**
     * @param node: Register Varnode
     * @return: Register mnemonic
     * <p>
     * Gets register mnemonic.
     */
    protected String getRegisterMnemonic(Varnode node) {
        return context.getRegister(node).getName();
    }


    /**
     * @param constant: Constant value
     * @return: Constant value without prefix
     * <p>
     * Removes the consts prefix from the constant.
     */
    protected String removeConstantPrefix(String constant) {
        return constant.replaceFirst("^(const:)", "");
    }


    protected String removeStackPrefix(String param) {
        Matcher matcher = Pattern.compile("^Stack\\[(0x\\d)\\]$").matcher(param);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

}

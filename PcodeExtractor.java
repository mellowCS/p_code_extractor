
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.EnumUtils;

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
        Boolean setGoto = false;
        try {
            CodeBlockIterator blockIter = simpleBM.getCodeBlocksContaining(currentSub.getTerm().getAddresses(), getMonitor());
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                if(setGoto) {
                    setGoto = false;
                    Tid direct = blocks.get(blocks.size()-1).getTerm().getJmps().get(0).getTerm().getGoto_().getDirect();
                    direct.setAddress(block.getFirstStartAddress().toString());
                    direct.setId(String.format("blk_%s", block.getFirstStartAddress().toString()));
                }
                ArrayList<Term<Blk>> newBlocks = iterateInstructions(createBlkTerm(block.getFirstStartAddress().toString(), null), listing, block);
                Term<Blk> lastBlock = newBlocks.get(newBlocks.size() - 1);
                if(protoLastInstructionIsDef(lastBlock)) {
                    String instrAddress = lastBlock.getTerm().getDefs().get(lastBlock.getTerm().getDefs().size()-1).getTid().getAddress();
                    protoAddJumpToCurrentBlock(lastBlock.getTerm(), instrAddress, block.getFirstStartAddress().toString(), null);
                    setGoto = true;
                }
                blocks.addAll(newBlocks);
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
        int instructionIndex = 0;
        InstructionIterator instructions = listing.getInstructions(codeBlock, true);
        long numberOfInstructionsInBlock = StreamSupport.stream(listing.getInstructions(codeBlock, true).spliterator(), false).count();
        ArrayList<Term<Blk>> blocks = new ArrayList<Term<Blk>>();
        blocks.add(block);

        for (Instruction instr : instructions) {
            protoIteratePcode(blocks, instr, instructionIndex, numberOfInstructionsInBlock);
            instructionIndex++;
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
        return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid), 0));
    }


    protected void protoIteratePcode(ArrayList<Term<Blk>> blocks, Instruction instruction, int instructionIndex, long numberOfInstructionsInBlock) {
        PcodeOp[] ops = instruction.getPcode(true);
        if(ops.length == 0) {
            protoAddJumpToCurrentBlock(blocks.get(blocks.size()-1).getTerm(), instruction.getAddress().toString(), instruction.getFallThrough().toString(), null);
            return;
        }
        int numberOfPcodeOps = ops.length;
        ArrayList<Term<Def>> temporaryDefStorage = new ArrayList<Term<Def>>();
        Boolean intraInstructionJumpOccured = false;

        for(int pcodeIndex = 0; pcodeIndex < numberOfPcodeOps; pcodeIndex++) {
            PcodeOp pcodeOp = ops[pcodeIndex];
            String mnemonic = pcodeOp.getMnemonic();

            if (this.jumps.contains(mnemonic)) {
                intraInstructionJumpOccured = protoProcessJump(blocks, instruction, pcodeOp, mnemonic, temporaryDefStorage, instructionIndex, numberOfInstructionsInBlock, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured);
            } else {
                temporaryDefStorage.add(createDefTerm(pcodeIndex, pcodeOp, instruction.getAddress()));
            }
        }

        if(intraInstructionJumpOccured) {
            Term<Blk> lastBlock = blocks.get(blocks.size() - 1);
            if(!temporaryDefStorage.isEmpty()) {
                handleMissingJumpAfterInstructionSplit(blocks, lastBlock, temporaryDefStorage, instruction);
            }
        }

        if(!temporaryDefStorage.isEmpty()) {
            blocks.get(blocks.size() - 1).getTerm().addMultipleDefs(temporaryDefStorage);
        }
    }


    protected void handleMissingJumpAfterInstructionSplit(ArrayList<Term<Blk>> blocks, Term<Blk> lastBlock, ArrayList<Term<Def>> temporaryDefStorage, Instruction instruction) {
        lastBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        protoAddJumpToCurrentBlock(lastBlock.getTerm(), instruction.getAddress().toString(), instruction.getFallThrough().toString(), null);
        blocks.add(createBlkTerm(instruction.getFallThrough().toString(), null));
        temporaryDefStorage.clear();
    }


    protected Boolean protoProcessJump(ArrayList<Term<Blk>> blocks, Instruction instruction, PcodeOp pcodeOp, String mnemonic, ArrayList<Term<Def>> temporaryDefStorage, 
    int instructionIndex, long numberOfInstructionsInBlock, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured) {

        int currentBlockCount = blocks.size();
        Term<Blk> currentBlock = blocks.get(currentBlockCount - 1);

        if(pcodeIndex < numberOfPcodeOps - 1) {
            if(!isCall(pcodeOp)) {
                intraInstructionJumpOccured = true;
                protoHandleIntraInstructionJump(blocks, temporaryDefStorage, currentBlock.getTerm(), instruction, pcodeOp, pcodeIndex, instructionIndex);
            } else {
                handleCallReturnPair(blocks, temporaryDefStorage, currentBlock, instruction, pcodeOp, pcodeIndex);
            }
        } else {
            // Case 2: jump at the end of pcode group but not end of ghidra generated block.
            if(instructionIndex < numberOfInstructionsInBlock - 1) {
                blocks.add(createBlkTerm(instruction.getFallThrough().toString(), null));
            }
            // Case 3: jmp at last pcode op at last instruction in ghidra generated block
            // If Case 2 is true, the 'currentBlk' will be the second to last block as the new block is for the next instruction
            if(pcodeOp.getOpcode() == PcodeOp.RETURN && currentBlock.getTid().getId().endsWith("_r")) {
                redirectCallReturn(currentBlock, instruction, pcodeOp);
                return intraInstructionJumpOccured;
            }
            currentBlock.getTerm().addMultipleDefs(temporaryDefStorage);
            currentBlock.getTerm().addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, mnemonic, instruction.getAddress()));
        }
        temporaryDefStorage.clear();

        return intraInstructionJumpOccured;
    }


    protected void protoHandleIntraInstructionJump(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Blk currentBlock, Instruction instruction, PcodeOp pcodeOp, int pcodeIndex, int instructionIndex) {
        if(instructionIndex > 0) {
            if(currentBlock.getDefs().size() == 0 && currentBlock.getJmps().size() == 0) {
                currentBlock.addMultipleDefs(temporaryDefStorage);
                currentBlock.addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress()));
            } else {
                if(temporaryDefStorage.size() > 0) {
                    protoAddJumpToCurrentBlock(currentBlock, instruction.getFallFrom().toString(), instruction.getAddress().toString(), "0");
                } else {
                    protoAddJumpToCurrentBlock(currentBlock, instruction.getFallFrom().toString(), instruction.getAddress().toString(), null);
                }
                protoCreateNewBlockForIntraInstructionJump(blocks, temporaryDefStorage, instruction, pcodeIndex, pcodeOp);
            }
        } else {
            currentBlock.addMultipleDefs(temporaryDefStorage);
            currentBlock.addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress()));
        }
        blocks.add(createBlkTerm(instruction.getAddress().toString(), String.valueOf(pcodeIndex + 1)));
        
    }


    protected Boolean isCall(PcodeOp pcodeOp){
        return (pcodeOp.getOpcode() == PcodeOp.CALL || pcodeOp.getOpcode() == PcodeOp.CALLIND);
    }


    protected void protoCreateNewBlockForIntraInstructionJump(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Instruction instruction, int pcodeIndex, PcodeOp pcodeOp){
        // Set the starting index of the new block to the first pcode instruction of the assembly instruction
        int nextBlockStartIndex;
        Term<Blk> newBlock;
        if(temporaryDefStorage.size() > 0) {
            nextBlockStartIndex = temporaryDefStorage.get(0).getTerm().getPcodeIndex();
            newBlock = createBlkTerm(instruction.getAddress().toString(), String.valueOf(nextBlockStartIndex));
        } else {
            newBlock = createBlkTerm(instruction.getAddress().toString(), null);
        }
        newBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        newBlock.getTerm().addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress()));
        blocks.add(newBlock);
    }


    protected void protoAddJumpToCurrentBlock(Blk currentBlock, String jmpAddress, String gotoAddress, String suffix) {
        int artificialJmpIndex;
        if(currentBlock.getDefs().size() == 0) {
            artificialJmpIndex = 1;
        } else {
            artificialJmpIndex = currentBlock.getDefs().get(currentBlock.getDefs().size() - 1).getTerm().getPcodeIndex() + 1;
        }
        Tid jmpTid = new Tid(String.format("instr_%s_%s", jmpAddress, artificialJmpIndex), jmpAddress);
        Tid gotoTid;
        if(suffix != null) {
            gotoTid = new Tid(String.format("blk_%s_%s", gotoAddress, suffix), gotoAddress);
        } else {
            gotoTid = new Tid(String.format("blk_%s", gotoAddress), gotoAddress);
        }
        currentBlock.addJmp(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid), artificialJmpIndex)));
    }


    protected Boolean protoLastInstructionIsDef(Term<Blk> block) {
        ArrayList<Term<Jmp>> jumps = block.getTerm().getJmps();
        ArrayList<Term<Def>> defs = block.getTerm().getDefs();

        if(defs.size() > 0 && jumps.size() == 0) {
            return true;
        }
        return false;
    }


    protected void handleCallReturnPair(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Term<Blk> currentBlock, Instruction instruction, PcodeOp pcodeOp, int pcodeIndex) {
        currentBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        Term<Jmp> jump = createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress());
        Term<Blk> returnBlock = createBlkTerm(instruction.getAddress().toString(), "r");
        jump.getTerm().getCall().setReturn_(new Label(new Tid(returnBlock.getTid().getId(), returnBlock.getTid().getAddress())));
        currentBlock.getTerm().addJmp(jump);
        blocks.add(returnBlock);
    }


    protected void redirectCallReturn(Term<Blk> currentBlock, Instruction instruction, PcodeOp pcodeOp) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s_r", instruction.getAddress().toString(), 0), instruction.getAddress().toString());
        Term<Jmp> ret = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, pcodeOp.getMnemonic(), createLabel(pcodeOp.getMnemonic(), pcodeOp, null), 0));
        currentBlock.getTerm().addJmp(ret);
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
        int stackPointerByteSize = (int) stackPointerRegister.getBitLength() / 8;
        Variable stackPointerVar = new Variable(stackPointerRegister.getName(), stackPointerByteSize, false);
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
        Boolean noReturn = funcMan.getFunctionAt(libSym.getAddress()).hasNoReturn();
        return new ExternSymbol(tid, libSym.getAddress().toString(), libSym.getName(), funcMan.getDefaultCallingConvention().getName(), args, noReturn);

    }


    /**
     * @param symbol:  External symbol
     * @return: internally called symbol for external symbol
     * 
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
     * 
     * Checks if current external symbol is referenced by a Thunk Function.
     * If so, the Thunk Function is the internally called function.
     */
    protected Boolean isThunkFunctionRef(Symbol def) {
        Reference[] refs = def.getReferences();
        if(refs.length == 0) {
            return false;
        }
        Address refAddr = def.getReferences()[0].getFromAddress();
        return funcMan.getFunctionContaining(refAddr) != null && funcMan.getFunctionContaining(refAddr).isThunk();
    }


    protected Boolean hasVoidReturn(Function func) {
        return func.hasNoReturn() || func.getReturn().getDataType().getName().equals("void");
    }


    /**
     * @param symbol:  Symbol used to get corresponding function
     * @return: new Arg ArrayList
     * 
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
    protected Term<Blk> createBlkTerm(String tidAddress, String suffix) {
        Tid blkTid;
        if(suffix != null) {
            blkTid = new Tid(String.format("blk_%s_%s", tidAddress, suffix), tidAddress);
        } else {
            blkTid = new Tid(String.format("blk_%s", tidAddress), tidAddress);
        }
        return new Term<Blk>(blkTid, new Blk());
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
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), createVariable(pcodeOp.getInput(1)), pCodeCount));
        } else if (mnemonic.equals("BRANCH") || mnemonic.equals("BRANCHIND")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), pCodeCount));
        } else if (mnemonic.equals("RETURN")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(mnemonic, pcodeOp, null), pCodeCount));
        }

        Term<Jmp> call = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, mnemonic, createCall(instr, mnemonic, pcodeOp), pCodeCount));
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
    protected Term<Def> createDefTerm(int pcodeIndex, PcodeOp pcodeOp, Address instrAddr) {
        Tid defTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pcodeIndex), instrAddr.toString());
        if (pcodeOp.getMnemonic().equals("STORE")) {
            return new Term<Def>(defTid, new Def(createExpression(pcodeOp), pcodeIndex));
            // cast copy instructions that have address outputs into store instructions
        } else if (pcodeOp.getMnemonic().equals("COPY") && pcodeOp.getOutput().isAddress()) {
            return new Term<Def>(defTid, new Def(new Expression("STORE", null, createVariable(pcodeOp.getOutput()), createVariable(pcodeOp.getInput(0))), pcodeIndex));
        }
        return new Term<Def>(defTid, new Def(createVariable(pcodeOp.getOutput()), createExpression(pcodeOp), pcodeIndex));
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
     * Create a Label based on the branch instruction. For indirect branches and calls, it consists of a Variable, for calls of a sub TID
     * and for branches of a blk TID.
     */
    protected Label createLabel(String mnemonic, PcodeOp pcodeOp, Address fallThrough) {
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

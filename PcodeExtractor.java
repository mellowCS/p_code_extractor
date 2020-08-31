

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import org.apache.commons.lang3.EnumUtils;
import org.python.jline.internal.Nullable;

import bil.*;
import term.*;
import symbol.ExternSymbol;
import serializer.Serializer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
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
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;

public class PcodeExtractor extends GhidraScript {
	
	List<String> jumps = new ArrayList<String>() {{
		add("BRANCH");
		add("CBRANCH");
		add("BRANCHIND");
		add("CALL");
		add("CALLIND");
		add("RETURN");
	}};
	
	Set<String> binOps = EnumUtils.getEnumMap(ExecutionType.BinOpType.class).keySet();
	Set<String> unOps = EnumUtils.getEnumMap(ExecutionType.UnOpType.class).keySet();
	Set<String> casts = EnumUtils.getEnumMap(ExecutionType.CastType.class).keySet();

	@Override
	protected void run() throws Exception {
		FunctionManager funcMan = currentProgram.getFunctionManager();
		SimpleBlockModel simpleBM = new SimpleBlockModel(currentProgram);
		Listing listing = currentProgram.getListing();
		VarnodeContext nodeContxt = new VarnodeContext(currentProgram, currentProgram.getProgramContext(), currentProgram.getProgramContext());
		
		Term<Program> program = createProgramTerm(funcMan, currentProgram, nodeContxt);
		Project project = createProject(program);
		program = iterateFunctions(program, funcMan, simpleBM, listing, nodeContxt);
		
		String jsonPath = getScriptArgs()[0];
		Serializer ser = new Serializer(project, jsonPath);
		ser.serializeProject();
		

	}
	
	
	protected Term<Program> iterateFunctions(Term<Program> program, FunctionManager funcMan, SimpleBlockModel simpleBM, Listing listing, VarnodeContext nodeContxt) {
		/*
		 * 
		 * Uses the function iterator to create sub terms for each functions and calls the block iterator to add all
		 * data to each corresponding sub (e.g. blk -> def/jmps)
		 * 
		 * */
		FunctionIterator functions = funcMan.getFunctionsNoStubs(true);
		for(Function func : functions) {
			if(!func.isThunk()) {
				Term<Sub> currentSub = createSubTerm(func);
				currentSub.getTerm().setBlocks(iterateBlocks(currentSub, simpleBM, listing, nodeContxt));
				program.getTerm().addSub(currentSub);
			}
		}
		
		return program;
	}
	
	
	protected Vector<Term<Blk>> iterateBlocks(Term<Sub> currentSub, SimpleBlockModel simpleBM, Listing listing, VarnodeContext nodeContxt) {
		/*
		 * 
		 * Iterates over all blocks and calls instruction iterator to add def and jmp terms to each block
		 * 
		 * */
		Vector<Term<Blk>> blocks = new Vector<Term<Blk>>();
		try {
			CodeBlockIterator blockIter = simpleBM.getCodeBlocksContaining(currentSub.getTerm().getAddresses(), getMonitor());
			while(blockIter.hasNext()) {
				CodeBlock block = blockIter.next();
				Term<Blk> currentBlk = createBlkTerm(block);
				blocks.add(iterateInstructions(currentBlk, listing.getInstructions(block, true), nodeContxt));
			}
		} 
		catch(CancelledException e) {
			System.out.printf("Could not retrieve all basic blocks comprised by function: %s\n", currentSub.getTerm().getName());
		}
		
		return blocks;
	}
	
	
	protected Term<Blk> iterateInstructions(Term<Blk> block, InstructionIterator instructions, VarnodeContext nodeContxt) {
		/*
		 * 
		 * iterate over pcode instructions and add either jmp or def term depending on the mnemonic
		 * 
		 * */
		int pCodeCount = 0;
		for (Instruction instr : instructions) {
			Address instrAddr = instr.getAddress();
			for(PcodeOp pcodeOp : instr.getPcode(true)) {
				String mnemonic = pcodeOp.getMnemonic();
				if(this.jumps.contains(mnemonic)) {
					Term<Jmp> jmp = createJmpTerm(instr, pCodeCount, pcodeOp, mnemonic, instrAddr, nodeContxt);
					block.getTerm().addJmp(jmp);
				} else {
					Term<Def> def = createDefTerm(pCodeCount, pcodeOp, instrAddr, nodeContxt);
					block.getTerm().addDef(def);
				}
				pCodeCount++;
			}
		}
		
		return block;
	}
	
	
	protected Project createProject(Term<Program> program) {
		Project project = new Project();
		CompilerSpec comSpec = currentProgram.getCompilerSpec();
		Register stackPointerRegister = comSpec.getStackPointer();
		Variable stackPointerVar = new Variable(stackPointerRegister.getName(), stackPointerRegister.getBitLength(), false);
		project.setProgram(program);
		project.setStackPointerRegister(stackPointerVar);
		
		return project;
	}
	
	
	protected Term<Program> createProgramTerm(FunctionManager funcMan, ghidra.program.model.listing.Program program, VarnodeContext nodeContxt) {
		/*
		 * set id to program's minimal address
		 * */
		Tid progTid = new Tid(String.format("prog_%s", program.getMinAddress().toString()), program.getMinAddress().toString());
		Vector<ExternSymbol> externalSymbols = new Vector<ExternSymbol>();
		SymbolIterator symIt = program.getSymbolTable().getExternalSymbols();
		while(symIt.hasNext()) {
			externalSymbols.add(createExternSymbol(funcMan, symIt.next(), nodeContxt));
		}
		return new Term<Program>(progTid, new Program(new Vector<Term<Sub>>(), externalSymbols));
	}
	
	
	protected ExternSymbol createExternSymbol(FunctionManager funcMan, Symbol symbol, VarnodeContext nodeContxt) {
		/*
		 * 
		 * */
		Tid tid = new Tid(String.format("sub_%s", symbol.getAddress().toString()), symbol.getAddress().toString());
		Vector<Arg> args = new Vector<Arg>();
		Function func = funcMan.getFunctionAt(symbol.getAddress());
		Parameter[] params = func.getParameters();
		for(Parameter param : params) {
			Arg arg = new Arg();
			if(param.isStackVariable()) {
				Variable stackVar = createVariable(param.getFirstStorageVarnode(), nodeContxt);
				arg.setLocation(new Expression("LOAD", stackVar));
				arg.setIntent("INPUT");
			} else if(param.isRegisterVariable()) {
				arg.setVar(createVariable(param.getFirstStorageVarnode(), nodeContxt));
				arg.setIntent("INPUT");
			}
			args.add(arg);
		}
	    if(!func.hasNoReturn() && !func.getReturn().getDataType().getName().equals("void")) {
	    	args.add(new Arg(createVariable(func.getReturn().getFirstStorageVarnode(), nodeContxt), "OUTPUT"));
		}
		return new ExternSymbol(tid, symbol.getAddress().toString(), symbol.getName(), funcMan.getDefaultCallingConvention().getName(), args);
	}
	
	
	protected Term<Sub> createSubTerm(Function func) {
		/*
		 * set each subroutine Tid to n.0.0 where n = subCount and set the address to the function's entry point
		 * create new Blk vector
		 * */
		Tid subTid = new Tid(String.format("sub_%s", func.getEntryPoint().toString()), func.getEntryPoint().toString());
		return new Term<Sub>(subTid, new Sub(func.getName(), func.getBody()));
	}
	
	
	protected Term<Blk> createBlkTerm(CodeBlock block) {
		/*
		 * set each block Tid to n.m.0 where n = subCount, m = blkCount and set the address to the first entry address of the block
		 * create new Def and Jmp vectors
		 * */
		Tid blkTid = new Tid(String.format("blk_%s", block.getFirstStartAddress().toString()), block.getFirstStartAddress().toString());
		return new Term<Blk>(blkTid, new Blk(new Vector<Term<Def>>(), new Vector<Term<Jmp>>()));
	}
	
	
	protected Term<Jmp> createJmpTerm(Instruction instr, int pCodeCount, PcodeOp pcodeOp, String mnemonic, Address instrAddr, VarnodeContext nodeContxt) {
		/*
		 * set each jmp Tid to n.m.p where n = subCount, m = blkCount, p = jmpCount
		 * TODO: process jmpKind
		 * */
		Tid jmpTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pCodeCount), instrAddr.toString());
		if(mnemonic.equals("CBRANCH")) {
			return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, nodeContxt, null), createVariable(pcodeOp.getInput(1), nodeContxt)));
		} else if (mnemonic.equals("BRANCH") || mnemonic.equals("BRANCHIND")) {
			return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, nodeContxt, null)));
		} else if (mnemonic.equals("RETURN")) {
			return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(mnemonic, pcodeOp, nodeContxt, null)));
		}
		
		return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, mnemonic, createCall(instr, mnemonic, pcodeOp, nodeContxt)));
	}
	
	
	protected Term<Def> createDefTerm(int pCodeCount, PcodeOp pcodeOp, Address instrAddr, VarnodeContext nodeContxt) {
		/*
		 * set each jmp Tid to n.m.p where n = subCount, m = blkCount, p = instrCount
		 * */
		Tid defTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pCodeCount), instrAddr.toString());
		if(pcodeOp.getMnemonic().equals("STORE")) {
			return new Term<Def>(defTid, new Def(createExpression(pcodeOp, nodeContxt)));
		} else if(pcodeOp.getMnemonic().equals("COPY") && pcodeOp.getOutput().isAddress()) {
			return new Term<Def>(defTid, new Def(new Expression("STORE", createVariable(pcodeOp.getOutput(), nodeContxt), createVariable(pcodeOp.getInput(0), nodeContxt))));
		}
		return new Term<Def>(defTid, new Def(createVariable(pcodeOp.getOutput(), nodeContxt), createExpression(pcodeOp, nodeContxt)));
	}

	
	protected Variable createVariable(Varnode node, VarnodeContext nodeContxt) {
		/*
		 * Set register name based on being a register, virtual register or ram address
		 * In case it is a virtual register, set 
		 * 
		 * */
		Variable var = new Variable();
		if(node.isRegister()) {
			var.setName(getRegisterMnemonic(nodeContxt, node));
			var.setSize(node.getSize());
			var.setIsVirtual(false);
		} 
		else if (node.isUnique()) {
			var.setName(renameVirtualRegister(node.getAddress().toString()));
			var.setSize(node.getSize());
			var.setIsVirtual(true);
		}
		else if (node.isConstant()) {
			var.setName(removeConstantPrefix(node.getAddress().toString()));
			var.setSize(node.getSize());
			var.setIsVirtual(false);
		}
		else if (node.isAddress()) {
			var.setName(node.getAddress().toString());
			var.setSize(node.getSize());
			var.setIsVirtual(false);
		}
		else if(node.isFree()) {
			var.setName(node.getAddress().toString());
			var.setSize(node.getSize());
			var.setIsVirtual(false);
		}
		return var;
	}
	
	
	protected Expression createExpression(PcodeOp pcodeOp, VarnodeContext cntxt) {
		String mnemonic = pcodeOp.getMnemonic();
		List<Variable> in = new ArrayList<Variable>();
		
		for(Varnode input : pcodeOp.getInputs()) {
			in.add(createVariable(input, cntxt));
		}
		
		int inputLen = in.size();
		
		if(inputLen == 1) {
			return new Expression(mnemonic, in.get(0));
		} 
		else if(inputLen == 2) {
			return new Expression(mnemonic, in.get(0), in.get(1));
		}
		else {
			return new Expression(mnemonic, in.get(0), in.get(1), in.get(2));
		}
	}
	
	
	protected Label createLabel(String mnemonic, PcodeOp pcodeOp, VarnodeContext nodeContxt, @Nullable Address fallThrough) {
		if (fallThrough == null) {
			if (mnemonic.equals("CALLIND") || mnemonic.equals("BRANCHIND") || mnemonic.equals("RETURN")) {
				return new Label(new Expression(mnemonic, createVariable(pcodeOp.getInput(0), nodeContxt)));
			}
			
			if(mnemonic.equals("CALL")) {
				return new Label(new Tid(String.format("sub_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
			}
			
			if(mnemonic.equals("BRANCH") || mnemonic.equals("CBRANCH")) {
				return new Label(new Tid(String.format("blk_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
			}
		} 
		
		return new Label(new Tid(String.format("blk_%s", fallThrough.toString()), fallThrough.toString()));
	}
	
	
	protected Call createCall(Instruction instr, String mnemonic, PcodeOp pcodeOp, VarnodeContext nodeContxt) {
		return new Call(createLabel(mnemonic, pcodeOp, nodeContxt, null), createLabel(mnemonic, pcodeOp, nodeContxt, instr.getFallThrough()));
	}
	
	
	protected String renameVirtualRegister(String address) {
		return "$U" + address.replaceFirst("^(unique:0+(?!$))", "");
	}
	
	
	protected String getRegisterMnemonic(VarnodeContext context, Varnode node) {
		return context.getRegister(node).getName();
	}
	
	
	protected long getNodeConstant(VarnodeContext context, Varnode node) {
		long constant = 0;
		ContextEvaluatorAdapter conEval = new ContextEvaluatorAdapter();
        try {
        	constant = context.getConstant(node, conEval);
		} catch(NotFoundException e) {
			System.out.printf("Could not find constant! %s", e);
		}
        
        return constant;
	}
	
	
	protected String removeConstantPrefix(String constant) {
		return constant.replaceFirst("^(const:)", "");
	}
	
	
	protected void printTerms(Term<Program> program) {
		for(Term<Sub> sub : program.getTerm().getSubs()) {
			System.out.printf("[SUB]: %s, (id): %s, (addr): %s\n\n", sub.getTerm().getName(), sub.getTid().getId(), sub.getTid().getAddress());
			for(Term<Blk> blk : sub.getTerm().getBlocks()) {
				System.out.printf("    [BLK]: -, (id): %s, (addr): %s\n\n", blk.getTid().getId(), blk.getTid().getAddress());
				for(Term<Def> def : blk.getTerm().getDefs()) {
					printDef(def);
				}
				for(Term<Jmp> jmp : blk.getTerm().getJmps()) {
					printJmp(jmp);
				}
				System.out.println("\n");
			}
		}
	}
	
	
	protected void printDef(Term<Def> definition) { 
		Variable output = definition.getTerm().getLhs();
		Expression input = definition.getTerm().getRhs();
		String mnemonic = input.getMnemonic();
		Tid defTid = definition.getTid();
		if(mnemonic.equals("STORE")) {
			if(input.getInput2() == null) {
				System.out.printf("        [DEF]: <%s> *%s = %s, (id): %s, (addr): %s\n", mnemonic, input.getInput0().getName(), input.getInput1().getName(), defTid.getId(), defTid.getAddress());
			} else {
				System.out.printf("        [DEF]: <%s> *[%s]%s = %s, (id): %s, (addr): %s\n", mnemonic, input.getInput0().getName(), input.getInput1().getName(), input.getInput2().getName(), defTid.getId(), defTid.getAddress());
			}
		}
		
		if(mnemonic.equals("LOAD")) {
			if(input.getInput1() == null) {
				System.out.printf("        [DEF]: <%s> %s = *%s, (id): %s, (addr): %s\n", mnemonic, output.getName(), input.getInput0().getName(), defTid.getId(), defTid.getAddress());
			} else {
				System.out.printf("        [DEF]: <%s> %s = *[%s]%s, (id): %s, (addr): %s\n", mnemonic, output.getName(), input.getInput0().getName(), input.getInput1().getName(), defTid.getId(), defTid.getAddress());
			}
		}
		
		if(this.binOps.contains(mnemonic)) {
			System.out.printf("        [DEF]: %s = %s <%s> %s, (id): %s, (addr): %s\n", output.getName(), input.getInput0().getName(), mnemonic, input.getInput1().getName(), defTid.getId(), defTid.getAddress());
		}
		
		if(this.unOps.contains(mnemonic) || this.casts.contains(mnemonic) || mnemonic.equals("COPY")) {
			System.out.printf("        [DEF]: <%s> %s = %s, (id): %s, (addr): %s\n", mnemonic,  output.getName(), input.getInput0().getName(), defTid.getId(), defTid.getAddress());
		}
		
		if(mnemonic.equals("SUBPIECE")) {
			System.out.printf("        [DEF]: <%s> %s = %s(%s), (id): %s, (addr): %s\n", mnemonic,  output.getName(), input.getInput0().getName(), input.getInput1().getName(), defTid.getId(), defTid.getAddress());
		}
	}
	
	
	protected void printJmp(Term<Jmp> jump) {
		Jmp jmp = jump.getTerm();
		Tid tid = jump.getTid();
		String mnemonic = jmp.getMnemonic();
		if(mnemonic.equals("CALL")) {
			Call call = jmp.getCall();
			System.out.printf("        [JMP]: <%s>, (target): %s, (return): %s, (id): %s, (addr): %s\n", mnemonic, call.getTarget().getDirect().getId(), call.getReturn_().getDirect().getId(), tid.getId(), tid.getAddress());
		} 
		
		if(mnemonic.equals("CALLIND")) {
			Call call = jmp.getCall();
			if(call.getReturn_().getDirect() == null) {
				System.out.printf("        [JMP]: <%s>, (target): %s, TAIL CALL, (id): %s, (addr): %s\n", mnemonic, call.getTarget().getIndirect().getInput0().getName(), tid.getId(), tid.getAddress());
			} else {
				System.out.printf("        [JMP]: <%s>, (target): %s, (return): %s, (id): %s, (addr): %s\n", mnemonic, call.getTarget().getIndirect().getInput0().getName(), call.getReturn_().getDirect().getId(), tid.getId(), tid.getAddress());
			}
		}
		
		if(mnemonic.equals("RETURN")) {
			System.out.printf("        [JMP]: <%s>, (goto): %s, (id): %s (addr): %s\n", mnemonic, jmp.getGoto_().getIndirect().getInput0().getName(), tid.getId(), tid.getAddress());
		}
		
		if(mnemonic.equals("BRANCH")) {
			System.out.printf("        [JMP]: <%s>, (goto): %s, (id): %s, (addr): %s\n", mnemonic, jmp.getGoto_().getDirect().getAddress(), tid.getId(), tid.getAddress());
		}
		
		if(mnemonic.equals("BRANCHIND")) {
			System.out.printf("        [JMP]: <%s>, (goto): %s, (id): %s, (addr): %s\n", mnemonic, jmp.getGoto_().getIndirect().getInput0().getName(), tid.getId(), tid.getAddress());
		}
		
		if(mnemonic.equals("CBRANCH")) {
			System.out.printf("        [JMP]: <%s>, (goto): %s, (if): %s, (id): %s, (addr): %s\n", mnemonic, jmp.getGoto_().getDirect().getId(), jmp.getCondition().getName(), tid.getId(), tid.getAddress());
		}
	}
	
	protected void printExternSymbols(Program program) {
		for(ExternSymbol sym : program.getExternSymbols()) {
			System.out.printf("[Symbol]: %s\n", sym.getName());
			for(Arg arg : sym.getArguments()) {
				if(arg.getVar() == null) {
					System.out.printf("    [Parameter]: %s from %s with size: %s, (intent): %s\n", arg.getLocation().getMnemonic(), arg.getLocation().getInput0().getName(), arg.getLocation().getInput0().getSize(), arg.getIntent());
				} else {
					System.out.printf("    [Parameter]: %s, (size): %s, (intent): %s\n", arg.getVar().getName(), arg.getVar().getSize(), arg.getIntent());
				}
			}
			System.out.println("\n");
		}
	}
	
}

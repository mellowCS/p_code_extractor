

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
		SymbolIterator symExtern = program.getSymbolTable().getExternalSymbols();
		while(symExtern.hasNext()) {
			Symbol ex = symExtern.next();
			externalSymbols.add(createExternSymbol(program, funcMan, ex, nodeContxt));
		}
		return new Term<Program>(progTid, new Program(new Vector<Term<Sub>>(), externalSymbols));
	}
	
	
	protected ExternSymbol createExternSymbol(ghidra.program.model.listing.Program program, FunctionManager funcMan, Symbol symbol, VarnodeContext nodeContxt) {
		/*
		 * 
		 * */
		Symbol libSym = getInternalCaller(program, funcMan, symbol);
		Tid tid = new Tid(String.format("sub_%s", libSym.getAddress().toString()), libSym.getAddress().toString());
		Vector<Arg> args = createArguments(funcMan, libSym, nodeContxt);
		return new ExternSymbol(tid, libSym.getAddress().toString(), libSym.getName(), funcMan.getDefaultCallingConvention().getName(), args);
		
	}
	
	
	protected Symbol getInternalCaller(ghidra.program.model.listing.Program program, FunctionManager funcMan, Symbol symbol) {
		SymbolIterator symDefined = program.getSymbolTable().getDefinedSymbols();
		Symbol candidate = symbol;
		while(symDefined.hasNext()) {
			Symbol def = symDefined.next();
			if(def.getName().equals(symbol.getName()) && !def.isExternal()) {
				if(!isThunkFunctionRef(def, funcMan)) {
					candidate = def;
				}
			}
		}
		return candidate;
	}
	
	
	protected Boolean isThunkFunctionRef(Symbol def, FunctionManager funcMan) {
		Address refAddr = def.getReferences()[0].getFromAddress();
		if(funcMan.getFunctionContaining(refAddr) != null && funcMan.getFunctionContaining(refAddr).isThunk()) {
			return true;
		}
		return false;
	}
	
	
	protected Vector<Arg> createArguments(FunctionManager funcMan, Symbol symbol, VarnodeContext nodeContxt) {
		Vector<Arg> args = new Vector<Arg>();
		Function func = funcMan.getFunctionAt(symbol.getAddress());
		Parameter[] params = func.getParameters();
		for(Parameter param : params) {
			args.add(specifyArg(param, nodeContxt));
		}
	    if(!func.hasNoReturn() && !func.getReturn().getDataType().getName().equals("void")) {
	    	args.add(new Arg(createVariable(func.getReturn().getFirstStorageVarnode(), nodeContxt), "OUTPUT"));
		}
	    
	    return args;
	}
	
	
	protected Arg specifyArg(Parameter param, VarnodeContext nodeContxt) {
		Arg arg = new Arg();
		if(param.isStackVariable()) {
			Variable stackVar = createVariable(param.getFirstStorageVarnode(), nodeContxt);
			arg.setLocation(new Expression("LOAD", stackVar));
			arg.setIntent("INPUT");
		} else if(param.isRegisterVariable()) {
			arg.setVar(createVariable(param.getFirstStorageVarnode(), nodeContxt));
			arg.setIntent("INPUT");
		}
		
		return arg;
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
	
}

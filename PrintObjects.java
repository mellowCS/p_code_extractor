import java.util.Set;

import org.apache.commons.lang3.EnumUtils;

import bil.ExecutionType;
import bil.Expression;
import bil.Variable;
import symbol.ExternSymbol;
import term.Arg;
import term.Blk;
import term.Call;
import term.Def;
import term.Jmp;
import term.Program;
import term.Sub;
import term.Term;
import term.Tid;

public class PrintObjects {
	
	public static void printTerms(Term<Program> program) {
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
	
	
	public static void printDef(Term<Def> definition) { 
		Set<String> binOps = EnumUtils.getEnumMap(ExecutionType.BinOpType.class).keySet();
		Set<String> unOps = EnumUtils.getEnumMap(ExecutionType.UnOpType.class).keySet();
		Set<String> casts = EnumUtils.getEnumMap(ExecutionType.CastType.class).keySet();
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
		
		if(binOps.contains(mnemonic)) {
			System.out.printf("        [DEF]: %s = %s <%s> %s, (id): %s, (addr): %s\n", output.getName(), input.getInput0().getName(), mnemonic, input.getInput1().getName(), defTid.getId(), defTid.getAddress());
		}
		
		if(unOps.contains(mnemonic) || casts.contains(mnemonic) || mnemonic.equals("COPY")) {
			System.out.printf("        [DEF]: <%s> %s = %s, (id): %s, (addr): %s\n", mnemonic,  output.getName(), input.getInput0().getName(), defTid.getId(), defTid.getAddress());
		}
		
		if(mnemonic.equals("SUBPIECE")) {
			System.out.printf("        [DEF]: <%s> %s = %s(%s), (id): %s, (addr): %s\n", mnemonic,  output.getName(), input.getInput0().getName(), input.getInput1().getName(), defTid.getId(), defTid.getAddress());
		}
	}
	
	
	public static void printJmp(Term<Jmp> jump) {
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
	
	public static void printExternSymbols(Program program) {
		for(ExternSymbol sym : program.getExternSymbols()) {
			System.out.printf("[Symbol]: %s @ %s\n", sym.getName(), sym.getAddress());
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

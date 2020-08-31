package term;

import java.util.Vector;
import com.google.gson.annotations.SerializedName;

import symbol.ExternSymbol;

public class Program {
	@SerializedName("subs")
	private Vector<Term<Sub>> subs;
	@SerializedName("extern_symbols")
	private Vector<ExternSymbol> externSymbols;
	
	public Program() {}
	
	public Program(Vector<Term<Sub>> subs) {
		this.setSubs(subs);
	}
	
	public Program(Vector<Term<Sub>> subs, Vector<ExternSymbol> externSymbols) {
		this.setSubs(subs);
		this.setExternSymbols(externSymbols);
	}
	
	
	public Vector<Term<Sub>> getSubs() {
		return subs;
	}
	
	public void setSubs(Vector<Term<Sub>> subs) {
		this.subs = subs;
	}
	
	public void addSub(Term<Sub> sub) {
		this.subs.add(sub);
	}

	public Vector<ExternSymbol> getExternSymbols() {
		return externSymbols;
	}

	public void setExternSymbols(Vector<ExternSymbol> extern_symbols) {
		this.externSymbols = extern_symbols;
	}
}

package term;

import java.util.Vector;
import com.google.gson.annotations.SerializedName;

public class Blk {
	@SerializedName("defs")
	private Vector<Term<Def>> defs;
	@SerializedName("jmps")
	private Vector<Term<Jmp>> jmps;
	
	public Blk() {}
	
	public Blk(Vector<Term<Def>> defs, Vector<Term<Jmp>> jmps) {
		this.setDefs(defs);
		this.setJmps(jmps);
	}

	public Vector<Term<Def>> getDefs() {
		return defs;
	}

	public void setDefs(Vector<Term<Def>> defs) {
		this.defs = defs;
	}

	public Vector<Term<Jmp>> getJmps() {
		return jmps;
	}

	public void setJmps(Vector<Term<Jmp>> jmps) {
		this.jmps = jmps;
	}
	
	public void addDef(Term<Def> def) {
		this.defs.add(def);
	}
	
	public void addJmp(Term<Jmp> jmp) {
		this.jmps.add(jmp);
	}
	
	
}
package term;

import bil.Expression;
import bil.Variable;

import com.google.gson.annotations.SerializedName;

public class Def {
	
	@SerializedName("lhs")
	private Variable lhs;
	@SerializedName("rhs")
	private Expression rhs;
	
	public Def() {}
	
	public Def(Expression rhs) {
		this.setRhs(rhs);
	}
	
	public Def(Variable lhs, Expression rhs) {
		this.setLhs(lhs);
		this.setRhs(rhs);
	}

	public Variable getLhs() {
		return lhs;
	}

	public void setLhs(Variable lhs) {
		this.lhs = lhs;
	}

	public Expression getRhs() {
		return rhs;
	}

	public void setRhs(Expression rhs) {
		this.rhs = rhs;
	}
}

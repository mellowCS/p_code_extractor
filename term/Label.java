package term;

import bil.Expression;
import com.google.gson.annotations.SerializedName;

public class Label {
	
	@SerializedName("direct")
	private Tid direct;
	@SerializedName("indirect")
	private Expression indirect;
	
	public Label(Tid tid) {
		this.setDirect(tid);
	}
	
	public Label(Expression expression) {
		this.setIndirect(expression);
	}
	 
	public Tid getDirect() {
		return direct;
	}
	
	public void setDirect(Tid direct) {
		this.direct = direct;
	}
	
	public Expression getIndirect() {
		return indirect;
	}
	
	public void setIndirect(Expression indirect) {
		this.indirect = indirect;
	}

}

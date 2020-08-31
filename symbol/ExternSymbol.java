package symbol;

import java.util.Vector;

import com.google.gson.annotations.SerializedName;

import term.Arg;
import term.Tid;

public class ExternSymbol {
	
	@SerializedName("tid")
	private Tid tid;
	@SerializedName("address")
	private String address;
	@SerializedName("name")
	private String name;
	@SerializedName("calling_convention")
	private String callingConvention;
	@SerializedName("arguments")
	private Vector<Arg> arguments;
	
	public ExternSymbol() {}
	
	public ExternSymbol(Tid tid, String address, String name, String callingConvention, Vector<Arg> arguments) {
		this.setTid(tid);
		this.setAddress(address);
		this.setName(name);
		this.setCallingConvention(callingConvention);
		this.setArguments(arguments);
	}
	
	public Tid getTid() {
		return tid;
	}
	
	public void setTid(Tid tid) {
		this.tid = tid;
	}
	
	public String getAddress() {
		return address;
	}
	
	public void setAddress(String address) {
		this.address = address;
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public String getCallingConvention() {
		return callingConvention;
	}
	
	public void setCallingConvention(String callingConvention) {
		this.callingConvention = callingConvention;
	}
	
	public Vector<Arg> getArguments() {
		return arguments;
	}
	
	public void setArguments(Vector<Arg> arguments) {
		this.arguments = arguments;
	}
}

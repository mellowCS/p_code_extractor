package term;

import bil.Variable;
import com.google.gson.annotations.SerializedName;

public class Project {
	@SerializedName("program")
	private Term<Program> program;
	@SerializedName("cpu_arch")
	private String cpuArch;
	@SerializedName("stack_pointer_register")
	private Variable stackPointerRegister;
	
	public Project() {}
	
	public Project(Term<Program> program, String cpuArch, Variable stackPointerRegister) {
		this.setProgram(program);
		this.setCpuArch(cpuArch);
		this.setStackPointerRegister(stackPointerRegister);
	}
	
	public Term<Program> getProgram() {
		return program;
	}
	
	public void setProgram(Term<Program> program) {
		this.program = program;
	}
	
	public String getCpuArch() {
		return cpuArch;
	}
	
	public void setCpuArch(String cpuArch) {
		this.cpuArch = cpuArch;
	}
	
	public Variable getStackPointerRegister() {
		return stackPointerRegister;
	}
	
	public void setStackPointerRegister(Variable stackPointerRegister) {
		this.stackPointerRegister = stackPointerRegister;
	}
}

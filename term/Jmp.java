package term;

import bil.ExecutionType;
import bil.Variable;

import com.google.gson.annotations.SerializedName;

public class Jmp {

    @SerializedName("type_")
    private ExecutionType.JmpType type;
    @SerializedName("mnemonic")
    private String mnemonic;
    @SerializedName("goto")
    private Label goto_;
    @SerializedName("call")
    private Call call;
    @SerializedName("condition")
    private Variable condition;

    public Jmp() {
    }

    public Jmp(ExecutionType.JmpType type, String mnemonic, Label goto_) {
        this.setType(type);
        this.setMnemonic(mnemonic);
        this.setGoto_(goto_);
    }

    public Jmp(ExecutionType.JmpType type, String mnemonic, Call call) {
        this.setType(type);
        this.setMnemonic(mnemonic);
        this.setCall(call);
    }

    public Jmp(ExecutionType.JmpType type, String mnemonic, Label goto_, Variable condition) {
        this.setType(type);
        this.setMnemonic(mnemonic);
        this.setGoto_(goto_);
        this.setCondition(condition);
    }

    public ExecutionType.JmpType getType() {
        return type;
    }

    public void setType(ExecutionType.JmpType type) {
        this.type = type;
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public void setMnemonic(String mnemonic) {
        this.mnemonic = mnemonic;
    }

    public Variable getCondition() {
        return condition;
    }

    public void setCondition(Variable condition) {
        this.condition = condition;
    }

    public Call getCall() {
        return call;
    }

    public void setCall(Call call) {
        this.call = call;
    }

    public Label getGoto_() {
        return goto_;
    }

    public void setGoto_(Label goto_) {
        this.goto_ = goto_;
    }

}

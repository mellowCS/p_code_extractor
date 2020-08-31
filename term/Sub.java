package term;

import java.util.Vector;
import com.google.gson.annotations.SerializedName;

import ghidra.program.model.address.AddressSetView;

public class Sub {
	@SerializedName("name")
	private String name;
	private AddressSetView addresses;
	@SerializedName("blocks")
	private Vector<Term<Blk>> blocks;
	
	public Sub() {}
	
	public Sub(String name, AddressSetView addresses) {
		this.setName(name);
		this.setAddresses(addresses);
	}
	
	public Sub(String name, Vector<Term<Blk>> blocks, AddressSetView addresses) {
		this.setName(name);
		this.setBlocks(blocks);
		this.setAddresses(addresses);
	}
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Vector<Term<Blk>> getBlocks() {
		return blocks;
	}

	public void setBlocks(Vector<Term<Blk>> blocks) {
		this.blocks = blocks;
	}
	
	public void addBlock(Term<Blk> block) {
		this.blocks.add(block);
	}

	public AddressSetView getAddresses() {
		return addresses;
	}

	public void setAddresses(AddressSetView addresses) {
		this.addresses = addresses;
	}
}

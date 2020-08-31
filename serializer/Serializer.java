package serializer;
import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.*;

import term.Project;
import term.Sub;


public class Serializer {
	private Project project;
	private String path;
	
	public Serializer() {}
	
	public Serializer(Project project, String path) {
		this.setProject(project);
		this.setPath(path);
	}

	public Project getProject() {
		return project;
	}

	public void setProject(Project project) {
		this.project = project;
	}
	
	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}
	
	public void serializeProject() {
		ExclusionStrategy strategy = new ExclusionStrategy() {
	        @Override
	        public boolean shouldSkipField(FieldAttributes field) {
	            if (field.getDeclaringClass() == Sub.class && field.getName().equals("addresses")) {
	                return true;
	            }
	            return false;
	        }
	 
	        @Override
	        public boolean shouldSkipClass(Class<?> clazz) {
	            return false;
	        }
	    };
	    
		Gson gson = new GsonBuilder().setPrettyPrinting().addSerializationExclusionStrategy(strategy).create();
		try {
			gson.toJson(project, new FileWriter(path));
		} catch (JsonIOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}

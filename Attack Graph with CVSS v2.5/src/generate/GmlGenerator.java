package generate;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import tree.Node;


public class GmlGenerator {
	
	
	// List of Marked Ids
	
	ArrayList<Integer> markedIds = new ArrayList<Integer>();
	
	// Default co-ordinates of all nodes
		int node_x_origin = 95;			
		int node_y_origin = 15;	
	// Default height and width of the boxes
		int h = 45;
		int w = 90;	
		
//		PrintWriter writer;
		
	/**
	 * A method to add details about each edge into a GML file.	
	 * @param sourceId is the ID of the source node of the edge.
	 * @param destId is the ID of the destination node of the edge.
	 * @param writer is the writer which is being currently used to write into the file.
	 */
		
	public void addEdge(int sourceId, int destId, PrintWriter writer)
	{
		writer.println("edge\n[");
		writer.println("source\t" + sourceId);
		writer.println("target\t" + destId);
		writer.println("graphics\n[");
		writer.println("fill\t" + "\"#000000\"");
		writer.println("targetArrow\t\"standard\"");
		writer.println("]");
		writer.println("]");
	}
		
		
		
	/**
	 * A method to add details about each node into a GML file.	
	 * @param node of type Node is the node to be added.
	 * @param id is the ID of the node to be added.
	 * @param writer is the writer which is being currently used to write into the file.
	 */
	public void addNode(Node node, int id, PrintWriter writer)
	{		
		writer.println("node\n[");
		writer.println("id " + id);
		writer.println("label \"" + node.getName() + "\"");
		writer.println("graphics\n[");
		writer.println("x\t" + node_x_origin);
		writer.println("y\t" + node_y_origin);
		writer.println("w\t" + w);
		writer.println("h\t" + h);			
		if(node.getType() == 0)
		{
			writer.println("type\t" + "\"roundrectangle\"");
			writer.println("fill\t" + "\"#FFB90F\"");
			
		}
		else if(node.getType() == 1)
		{
			writer.println("type\t" + "\"diamond\"");
			writer.println("fill\t" + "\"#00FF33\"");
			
		}
		else
		{
			writer.println("type\t" + "\"ellipse\"");			
			writer.println("fill\t" + "\"#0BB5FF\"");
		}
		
		writer.println("outline\t" + "\"#000000\"");
		writer.println("]");
		writer.println("LabelGraphics\n[");
		writer.println("text\t\"" + node.getName() + "\"");
		writer.println("fontSize\t" + 12);
		writer.println("fontName\t\"Dialog\"");
		writer.println("anchor\t\"c\"");
		writer.println("]");
		writer.println("]");
		
	}
	
	/**
	 * A method to generate GML files based on the input attack graph.
	 * @param nodes is the ArrayList<Node> that contains information about the nodes in the attack graph.
	 * @param modelName is the name of the attack graph model inputed.
	 * @return true if the file generation was successful, else false.
	 */
	public boolean generateGML(ArrayList<Node> nodes, String modelName)
	{
		
		/**
		 * Creating an object of GMLGenerator to access methods addNode and addEdge
		 */
		
		GmlGenerator gg = new GmlGenerator();
		
		
		/**
		 * Generate the GML folder for storing the output GML files for the models
		 */
		File dir = new File("GML");
		dir.mkdir();
		
		/**
		 * Generate the ModelName.gml file for the input model
		 */
		String fileName = modelName + ".gml";
		Path file = Paths.get(dir + File.separator + fileName);			
		try 
		{
			// Create the empty file with default permissions, etc.
			if(!file.toFile().exists())
				Files.createFile(file);
			
			PrintWriter writer = new PrintWriter(dir + File.separator + fileName, "UTF-8");
			writer.println("Creator \"Swapnanjan Chatterjee <schatt@iastate.edu>\"");
//			writer.println("# Auto Genrated GML file for input Model: " + modelName);
			writer.println("graph");
			writer.println("[");
			writer.println("hierarchic\t1");
			writer.println("label\t\"\"");
			writer.println("directed\t1");
			
			int id = 0;
			int sourceId = 0;
			int destId = 0;
			for(int i=0; i<nodes.size(); i++)
			{				
				id = i;
				if(!markedIds.contains(id))
				{
				gg.addNode(nodes.get(i), id, writer);				
				markedIds.add(id);
				}
				sourceId = id;
				for(int j=0; j<nodes.get(i).getChildren().size(); j++)
				{					
					for(int k=0; k<nodes.size(); k++)
						if(nodes.get(k).getName().equals(nodes.get(i).getChildren().get(j).getName()))
							id = k;
						else
							continue;
				
					if(!markedIds.contains(id))
					{
					gg.addNode(nodes.get(i).getChildren().get(j), id, writer);
					markedIds.add(id);
					}
					destId = id;					
					gg.addEdge(sourceId, destId, writer);					
				}								
			}
			
			writer.println("]");
			writer.close();
			return true;
		}
		catch (FileAlreadyExistsException x) {				
			System.err.format("File name already exists", file);
			return false;
		}
		catch (IOException x) {
			// Some other sort of failure, such as permissions.				
			System.err.format("CreateFile error: ", x);
			return false;
		}
	}

}

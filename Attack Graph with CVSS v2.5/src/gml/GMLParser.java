package gml;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import tree.Node;



public class GMLParser {
	
	
	/**
	 * A static class that stores information about the GML node ID and name.
	 * @author Swapnanjan Chatterjee, schatt@iastate.edu
	 *
	 */
	public static class GMLNodes {
		
		protected int  id;
		protected String name;
		
		
		GMLNodes()
		{
			this.id = 0;
			this.name = "";
		}
		
		/**
		 * A parameterized constructor to store the ID and name of each GML node.
		 * @param id is the numeric ID of a GML node.
		 * @param name is the name of the GML node.
		 */
		public GMLNodes(int id, String name)
		{
			this.id = id;
			this.name = name;
		}
				
		
	}
	
	
	
	/**
	 * gn is an ArrayList<GMLNodes> to store all the GML nodes.
	 */
	private ArrayList<GMLNodes> gn = new ArrayList<GMLNodes>();
	/**
	 * n is an ArrayList<Node> to store all the nodes in the attacck graph.
	 */
	private ArrayList<Node> n = new ArrayList<Node>();

	/**
	 * A method to parse the GML input file.
	 * @param path is the file-path to the input GML file. 
	 * @param fileName is the input GML filename.
	 * @return ArrayList<Node> that will cotain information about the structure of the entire attack graph.
	 */
	@SuppressWarnings("resource")
	public ArrayList<Node> parseGML(String path, String fileName)
	{
		try{					
			/*
			 *  Open the file that is mentioned in the file (Along with the path)
			 */
			FileInputStream fstream = new FileInputStream(path+ File.separator + fileName);
			// Get the object of DataInputStream
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));			  
			String strLine;
			int lineNumber = 0;
			
			String nodeID, nodeName, nodeType;
			int id = 0;
			int type = 3;
			int source = 0, target = 0;
			String sourceName = new String();
			String destName = new String();			
			
			// ** Read File Line By Line **
			while ((strLine = br.readLine()) != null)
			{
				lineNumber++;
				strLine = strLine.replaceAll("\t", "");
				
				if(strLine.equalsIgnoreCase("node"))
				{	
					
					while(!strLine.contains("id"))
					{
						strLine = br.readLine();
						strLine = strLine.replaceAll("\t", " ");
						lineNumber++;
					}
					String[] temp = strLine.split("id");
					temp = temp[1].split(" ");
					nodeID = temp[1].replaceAll("\"", "");
					id = Integer.parseInt(nodeID);
//					System.out.println("Line Number: " + lineNumber + " " + strLine);
//					System.out.println("Node ID: " + id);
					
					
					
					
					while(!strLine.contains("label"))
					{																														
						strLine = br.readLine();
						strLine = strLine.replaceAll("\t", " ");
						lineNumber++;
					}
					
					temp = strLine.split("label");
					temp = temp[1].split(" ");
					nodeName = temp[1].replaceAll("\"", "");
//					System.out.println("Line Number: " + lineNumber + " " + strLine);
//					System.out.println("Node Name: " + nodeName);
					
					while(!strLine.contains("type"))
					{
						strLine = br.readLine();
						strLine = strLine.replaceAll("\t", " ");
						lineNumber++;
					}
					
					temp = strLine.split("type");
					temp = temp[1].split(" ");
					nodeType = temp[1].replaceAll("\"", "");
					
					if(nodeType.equalsIgnoreCase("diamond"))
						type = 1;
					else if (nodeType.equalsIgnoreCase("ellipse")) 
						type = 2;
					else if(nodeType.equalsIgnoreCase("roundrectangle"))
						type = 0;
					else
						throw new IOException("Error while parsing .gml file at line: " + lineNumber + "\nInvalid Node Type (Allowed: \"ellipse\", \"diamond\", \"roundrectangle\"");
//					System.out.println("Line Number: " + lineNumber + " " + strLine);
//					System.out.println("Node Type: " + nodeType + " Type: " + type);
					
					n.add(new Node(nodeName, type));
					gn.add(new GMLNodes(id, nodeName));
				}
				
				
				
				
				if(strLine.equalsIgnoreCase("edge"))
				{
					while(!strLine.contains("source"))
					{																														
						strLine = br.readLine();
						strLine = strLine.replaceAll("\t", " ");
						lineNumber++;
					}
					
					String[] temp = strLine.split("source");
					temp = temp[1].split(" ");
					source = Integer.parseInt(temp[1]);
					
					
					while(!strLine.contains("target"))
					{																														
						strLine = br.readLine();
						strLine = strLine.replaceAll("\t", " ");
						lineNumber++;
					}
					
					temp = strLine.split("target");
					temp = temp[1].split(" ");
					target = Integer.parseInt(temp[1]);
					
					
					for(GMLNodes g : gn)
					{
						if(source == g.id)
							sourceName = g.name;
						if(target == g.id)
							destName = g.name;
						
					}
					
					for(Node node : n)
					{
						if(node.getName().equals(sourceName))
						{
							for(Node node1 : n)
							{
								if(node1.getName().equals(destName))
								{
									node.addChild(node1);
									node1.addParent(node);
								}
									
							}
						}
					}
					
				}
				
				
				
				
//				System.out.println("Line Number: " + lineNumber + " " + strLine);
			}
			
						
						
		}
		catch(Exception e)
		{			
			System.err.println(e);
		}
					
		return n;
	}

}

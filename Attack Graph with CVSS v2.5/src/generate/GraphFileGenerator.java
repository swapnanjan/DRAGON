package generate;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import tree.Node;

import com.ctc.wstx.evt.WProcInstr;


public class GraphFileGenerator {

	/**
	 * A method to generate an attack graph file from the input GML file.
	 * @param nodes is the ArrayList<Node> that contains information about the structure of the attack graph.
	 * @param modelName is the name of the input attack graph model.	
	 * @return true if the file generation was successful, else return false.
	 */
	public boolean generateGraph(ArrayList<Node> nodes, String modelName)
	{
		
		/**
		 * Generate the GML folder for storing the output GML files for the models
		 */
		File dir = new File("Graphs");
		dir.mkdir();

		/**
		 * Generate the ModelName.txt file for the input model
		 */
		String fileName = modelName + ".txt";
		Path file = Paths.get(dir + "\\" + fileName);			
		try 
		{
			// Create the empty file with default permissions, etc.
			if(!file.toFile().exists())
				Files.createFile(file);

			PrintWriter writer = new PrintWriter(dir + "\\" + fileName, "UTF-8");
			writer.println("# Auto Generated Attack Graph file from .gml file");

			ArrayList<String> pnodes = new ArrayList<String>();
			ArrayList<String> enodes = new ArrayList<String>();
			ArrayList<String> lnodes = new ArrayList<String>();
			for(int i=0; i<nodes.size(); i++)
			{
				if(nodes.get(i).getType() == 1)				
					pnodes.add(nodes.get(i).getName());					
				else if(nodes.get(i).getType() == 2)
					enodes.add(nodes.get(i).getName());
				else if(nodes.get(i).getType() == 0)
					lnodes.add(nodes.get(i).getName());
				else
				{
					System.err.print("\nIllegal Node type (Exception thrown!)");
					throw new IOException();
				}

			}

			/**
			 * For writing the pnodes to attack graph file
			 */			
			writer.print("pnodes : ");
			for(int i=0; i<pnodes.size(); i++)
			{
				writer.print(pnodes.get(i));
				if(i == pnodes.size()-1)
					writer.print(";");
				else
					writer.print(", ");
			}

			/**
			 * For writing the enodes to attack graph file
			 */
			writer.println();
			writer.print("enodes : ");
			for(int i=0; i<enodes.size(); i++)
			{				
				writer.print(enodes.get(i));			
				if(i == enodes.size()-1)
					writer.print(";");
				else
					writer.print(", ");
			}

			/**
			 * For writing the lnodes to attack graph file
			 */
			writer.println();
			writer.print("lnodes : ");
			for(int i=0; i<lnodes.size(); i++)
			{				
				writer.print(lnodes.get(i));			
				if(i == lnodes.size()-1)
					writer.print(";");
				else
					writer.print(", ");
			}

			/**
			 * For writing root 
			 */
			writer.println();
			writer.println("root : " + nodes.get(0).getName());

			/**
			 * For writing goals 
			 */
			writer.println("goals:");
			for(int i=0; i<nodes.size(); i++)
			{
				if((nodes.get(i).getType() == 1 || nodes.get(i).getType() == 2) && nodes.get(i).getChildren().size() > 0)
				{
					for(int j=0; j<nodes.get(i).getChildren().size(); j++)
					{						
						if(nodes.get(i).getChildren().get(j).getType() == 1 || nodes.get(i).getChildren().get(j).getType() == 2)
						{
//							if(i > 0)
//								writer.println("");
							writer.print(nodes.get(i).getName());
							writer.print("-->");
							writer.print(nodes.get(i).getChildren().get(j).getName());							
							writer.print(";");
							writer.println();
						}
					}					

				}
			}			
			writer.print("sloag");
			writer.println();
			
			/**
			 * For writing leaves 
			 */
			writer.println("leaves:");
			for(int i=0; i<nodes.size(); i++)
			{
				if((nodes.get(i).getType() == 1 || nodes.get(i).getType() == 2) && nodes.get(i).getChildren().size() > 0)
				{
					for(int j=0; j<nodes.get(i).getChildren().size(); j++)
					{						
						if(nodes.get(i).getChildren().get(j).getType() == 0)
						{							
							writer.print(nodes.get(i).getName());
							writer.print("-->");
							writer.print(nodes.get(i).getChildren().get(j).getName());
//							if(j == nodes.get(i).getChildren().size()-1)
//							{
								writer.print(";");
								writer.println();
//							}
//							else
//								writer.print(", ");
						}
					}										
				}
			}
			
			writer.println("sevael");
			writer.println("END");
			/**
			 * Closing the file (Writing finished)
			 */

			writer.close();

		}catch(Exception e){
			System.out.println("Exception: " + e);
			return false;
		}

		return true;
	}
}

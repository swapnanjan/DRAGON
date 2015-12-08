package generate;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Random;

import parser.TreeParser;

import tree.*;


public class CVSSFileGenerator {
	
	
	/**
	 * A method to generate a file containing CVSS impact parameters for the nodes in the graph. Calls method generateFile()
	 * for performing the action.
	 * @param dir is the directory (path to the directory) where the input attack graph files reside. 
	 * @param numberOfFiles is the number of different CVSS files to generate.
	 * @return true if the files were successfully created, else false. 
	 */
	public boolean generateFiles(String dir, int numberOfFiles)
	{
			
//		CVSSFileGenerator fg = new CVSSFileGenerator();							

		String dirName = "TestFile";
		File directory = new File(dirName);
		directory.mkdir();

		



		File folder = new File(dir);
		File[] listOfFiles = folder.listFiles();			

		for (int i = 0; i < listOfFiles.length; i++) 
		{
			if (listOfFiles[i].isFile()) 
			{
				/**
				 * Parsing the nodes to generate random CVSS files
				 */
							
				ArrayList<Node> nodes = new ArrayList<Node>(); 
				
				TreeParser tp = new TreeParser();		
				tp.parse(dir+listOfFiles[i].getName(), nodes);		  		
				ArrayList<Node> allNodes = new ArrayList<Node>();				

//				System.out.println("File: " + listOfFiles[i].getName());
				int leaves = 0;
				for(int w=0; w<nodes.size(); w++)
				{					
					if(nodes.get(w).getType() == 1 || nodes.get(w).getType() == 0)
					{
						if(nodes.get(w).getType() == 0)
							leaves++;
						allNodes.add(nodes.get(w));
					}
				} 
				

				/**
				 * Finding the name of the model files and then generating random CVSS test files
				 */

				String[] temp = listOfFiles[i].getName().split(".txt");		        
				String modelName = temp[0];
				try {
					generateFile(dirName, modelName, allNodes, numberOfFiles);
				} catch (FileNotFoundException e) {
					System.out.println("The file " + modelName + ".txt was not found.");
					e.printStackTrace();
					return false;
				} catch (UnsupportedEncodingException e) {
					System.out.println("Unsuccessful in Performing requested taks.");
					e.printStackTrace();
					return false;
				}
			}
			else
				continue;
		}

		return true;
	}
	
	/**
	 * A method to generate the individual CVSS files, for assigning random values to the nodes in the attack graph.
	 * @param directory is the location (path to the directory), where the attack graph input files are stored.
	 * @param modelName is the name of the input attack graph model.
	 * @param candidates is an ArrayList<Node> that contains nodes, who can be assigned the random CVSS impact values.
	 * @param numberOfFiles is the total number of random files to generate.
	 * @throws FileNotFoundException if the filename is not found in the input location.
	 * @throws UnsupportedEncodingException if the file cannot be read.
	 */

	public void generateFile(String directory, String modelName, ArrayList<Node> candidates, int numberOfFiles)
			throws FileNotFoundException, UnsupportedEncodingException {
		String dirName = modelName + "_test";
		File dir = new File(directory + File.separator + dirName);
		dir.mkdir();
		
		for(File file: dir.listFiles())
			file.delete();
				 		
		for (int k = 1; k <= numberOfFiles; k++)
		{
			String fileName = "test" + k + ".txt";
			Path file = Paths.get(directory + File.separator + dirName + File.separator + fileName);			
			try 
			{
				// Create the empty file with default permissions, etc.
				if(!file.toFile().exists())
					Files.createFile(file);
				PrintWriter writer = new PrintWriter(directory + File.separator + dirName + File.separator + fileName, "UTF-8");
				writer.println("# Auto Genrated File with random parameters for the Model");
				writer.println("# Very Lo=1, Lo=2, Lo Med=3, Hi Med=4, Hi=5, Very Hi=6");
				writer.println("# Root Node always has configuration: [7,7,7]");
				writer.println("START");
				
				for(int j=1; j<candidates.size(); j++)
				{					
									
					double random = Math.random();					
					if(random < 0.5)
						continue;
					else
					{		/*													
							double randomC = 13*Math.random();
							double randomI = 13*Math.random();
							double randomA = 13*Math.random();
							*/							
							int c = 1 + (int)(6*Math.random());
							int i = 1 + (int)(6*Math.random());
							int a = 1 + (int)(6*Math.random());
							
							/*
							if(randomC < 0.33)
								c = 1;
							else if (randomC >=  0.33 && randomC < 0.66) 							
								c = 2;							
							else
								c = 3;
							
							if(randomI < 0.33)
								i = 1;
							else if (randomI >=  0.33 && randomI < 0.66) 							
								i = 2;							
							else
								i = 3;
							
							if(randomA < 0.33)
								a = 1;
							else if (randomA >=  0.33 && randomA < 0.66) 							
								a = 2;							
							else
								a = 3;
							*/
																												
							writer.println(candidates.get(j).getName() + ":[" + c + "," + i + "," + a + "]");						
					}
						
				}
				
				writer.println("END");
				writer.close();				
			}
			catch (FileAlreadyExistsException x) {				
				System.err.format("File name already exists", file);
			}
			catch (IOException x) {
				// Some other sort of failure, such as permissions.				
				System.err.format("CreateFile error: ", x);
			}
		}
		
		System.out.println("Successfully created " + numberOfFiles + " test files for " + modelName + "\n");
	}

}

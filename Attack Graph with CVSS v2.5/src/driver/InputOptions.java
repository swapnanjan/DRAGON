package driver;

import generate.GraphFileGenerator;
import gml.GMLParser;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.swing.JPopupMenu.Separator;

import tree.Node;
import verify.TreeValidator;

public class InputOptions {

	/**
	 * A method to take input from user whether they want to input a .txt file or .gml file
	 * Or, perhaps want to draw their own graph
	 * @return choice which is an integer, containing the input choice the user entered. Valid responses are: 1, 2, or 3 only.	 
	 */

	@SuppressWarnings("resource")
	public String graphInputOption()
	{				
		Scanner scan = new Scanner(System.in);
		System.out.println();
		System.out.println("List of Input options:");
		System.out.println("-----------------------------");
		System.out.println("Option 1: To Input attack graph from a .txt file, Press 1");
		System.out.println("Option 2: To input attack graph from a .gml file, Press 2");
		System.out.println("Option 3: To input attack graph by creating your  own atack graph file in the editor press 3");
		System.out.println("Please enter your choice: ");
		String choice  = scan.nextLine();		
		while(!(choice.equals("1") || choice.equals("2") || choice.equals("3")))
		{
			System.err.println("Invalid choice! (Allowed inputs 1, 2, 3)");
			System.out.println("List of Input options:");
			System.out.println("-----------------------------");
			System.out.println("Option 1: To Input attack graph from a .txt file, Press 1");
			System.out.println("Option 2: To input attack graph from a .gml file, Press 2");
			System.out.println("Option 3: To input attack graph by creating your own atack graph file in the editor press 3");
			System.out.println("Please enter your choice: ");
			choice = scan.nextLine();
		}				

		return choice;
	}


	/**
	 * A Method to input filename containing the CVSS values for the model
	 * @return The full file-path + file-name of the input file provided by the user. Returns null if no file exists.  
	 */

	public String inputCVSS()
	{
		System.out.println("Enter the CVSS filename (if the file is inside the CVSS folder, or provide absolute path): ");
		Scanner scan = new Scanner(System.in);
		String fileName = scan.nextLine();
		while(!fileName.endsWith(".txt"))
		{
			System.out.println("The file must be of type \".txt\"");
			System.out.println("Enter the CVSS filename (if the file is inside the CVSS folder, or provide absolute path): ");
			fileName = scan.nextLine();
		}

		String cvssFilePath = new String();
		String cvssFileName = new String();			

		if(fileName.startsWith(File.separator) || fileName.startsWith(":", 1))
		{
			cvssFilePath = fileName.substring(0, fileName.lastIndexOf(File.separator));
			cvssFileName = fileName.substring(fileName.lastIndexOf(File.separator)+1, fileName.length());
		}
		else
		{
			cvssFilePath = "CVSS";
			cvssFileName = fileName.substring(fileName.lastIndexOf(File.separator)+1, fileName.length());			
		}

		Path file = Paths.get(cvssFilePath + File.separator + cvssFileName);
		if(file.toFile().exists())
		{
			String fullFilePath = cvssFilePath + File.separator + cvssFileName;		
			return fullFilePath;
		}
		else
		{			
			return "null";
		}
	}
	
	
	/**
	 * A Method to input filename containing the CVSS Preference values for the model.
	 * @return The full file-path + file-name of the input file provided by the user. Returns null if no file exists.
	 */

	public String inputCVSSPreferences()
	{
		System.out.println("Enter the CIA Preference filename (if the file is inside the CVSSPreferences folder, or provide absolute path): ");
		Scanner scan = new Scanner(System.in);
		String fileName = scan.nextLine();
		while(!fileName.endsWith(".txt"))
		{
			System.out.println("The file must be of type \".txt\"");
			System.out.println("Enter the CVSS filename (if the file is inside the CVSSPreferences folder, or provide absolute path): ");
			fileName = scan.nextLine();
		}

		String cvssFilePath = new String();
		String cvssFileName = new String();			

		if(fileName.startsWith(File.separator) || fileName.startsWith(":", 1))
		{
			cvssFilePath = fileName.substring(0, fileName.lastIndexOf(File.separator));
			cvssFileName = fileName.substring(fileName.lastIndexOf(File.separator)+1, fileName.length());
		}
		else
		{
			cvssFilePath = "CVSSPreferences";
			cvssFileName = fileName.substring(fileName.lastIndexOf(File.separator)+1, fileName.length());			
		}

		Path file = Paths.get(cvssFilePath + File.separator + cvssFileName);
		if(file.toFile().exists())
		{
			String fullFilePath = cvssFilePath + File.separator + cvssFileName;		
			return fullFilePath;
		}
		else
		{			
			return "null";
		}
	}




	/**
	 * Method to perform task after user has pointed out preffered method of input
	 * @param choice is a String on which the switch-case statements operate 
	 *(1 = Input from '.txt' file, 2 = Input from '.gml' file, and 3 = Create own '.gml' file in the editor)
	 *
	 *@return the path and filename of the attack graph as a List<String>
	 */

	@SuppressWarnings({ "resource", "unused" })
	public List<String> processChoice(String choice)
	{
		Scanner scan1 = new Scanner(System.in);

		// A String that stores the OS separator for that system (Windows/Unix or some other machine) 

		String sep = File.separator;

		/**
		 *	Location of the file & filename to be parsed 
		 */			
		String attGraphFilename = new String();
		// For normal txt file input
		String attGraphPath = new String();
		// For GML file input
		String attGraphGMLPath = new String();		


		/**
		 * Switch-case statements to check how the user wants to input the attack graph
		 */
		switch (choice) {
		case "1": System.out.println("Enter the name of the file(Place file inside the Graphs folder or provide absolute path): ");
		attGraphFilename = scan1.nextLine(); 
		while(!attGraphFilename.contains(".txt"))
		{
			System.out.println("The file must be of type \".txt\"");
			System.out.println("Enter the name of the file(Place file inside the Graphs folder or provide absolute path): ");
			attGraphFilename = scan1.nextLine();
		}


		// This means user provided absolute path
		if(attGraphFilename.startsWith(File.separator) || attGraphFilename.startsWith(":", 1))
		{
			attGraphPath = attGraphFilename.substring(0, attGraphFilename.lastIndexOf(sep));
			attGraphFilename = attGraphFilename.substring(attGraphFilename.lastIndexOf(sep)+1, attGraphFilename.length());
		}
		else
		{
			attGraphPath = "Graphs";
			attGraphFilename = attGraphFilename.substring(attGraphFilename.lastIndexOf(sep)+1, attGraphFilename.length());
		}

		break;

		case "2": System.out.println("Enter the name of the file(Place file inside the GML folder or provide absolute path): ");
		attGraphFilename = scan1.nextLine();
		while(!attGraphFilename.contains(".gml"))
		{
			System.out.println("The file must be of type \".gml\"!");
			System.out.println("Enter the name of the file(Place file inside the GML folder or provide absolute path): ");
			attGraphFilename = scan1.nextLine();
		}

		if(attGraphFilename.startsWith(File.separator) || attGraphFilename.startsWith(":", 1))
		{
			attGraphGMLPath = attGraphFilename.substring(0, attGraphFilename.lastIndexOf(sep));
			attGraphPath = "Graphs";
			attGraphFilename = attGraphFilename.substring(attGraphFilename.lastIndexOf(sep)+1, attGraphFilename.length());				
		}	
		else
		{
			attGraphGMLPath = "GML";
			attGraphPath = "Graphs";
			attGraphFilename = attGraphFilename.substring(attGraphFilename.lastIndexOf(sep)+1, attGraphFilename.length());
		}

		String modelName = attGraphFilename.substring(attGraphFilename.lastIndexOf(sep)+1, attGraphFilename.lastIndexOf("."));

		GMLParser gp = new GMLParser();
		//ArrayList of nodes to set-up the attack Graph file
		ArrayList<Node> nodes = new ArrayList<Node>();
		nodes = gp.parseGML(attGraphGMLPath, attGraphFilename);
		
		// Creating an object of TreeValidator for validating
		TreeValidator tv = new TreeValidator();		
				
		/**
		 * For validating the input graph .txt file, so that it doesn't contain redundant node names
		 */			
		boolean check = tv.checkGMLValidity(nodes);
		
		/**
		 * For validating the leaf nodes don't have any children
		 */
		
		boolean check2 = tv.checkLeafValidity(nodes);
		
		if(check == true && check2 == true)
		{
		GraphFileGenerator gfg = new GraphFileGenerator();
		gfg.generateGraph(nodes, modelName);
		}
		else
		{	
			if(check == false)
				System.out.println("Error: The Attack graph cannot have different nodes with same name");
			if(check2 == false)
				System.out.println("Error: Some of the leaf nodes(Configurations) have children");
			
			System.out.println("Exiting the program ...");			
			System.exit(0);
		}

		attGraphFilename = modelName;
		nodes.clear();

		break;

		case "3": System.out.println("Invoking the Graph Editor ...");		
		try {
			Process p = Runtime.getRuntime().exec("C:"+ sep + "Program Files (x86)" + sep + "yWorks" + sep + "yEd" + sep + "yEd.exe");

			System.out.println("Are you done creating the input file and saving it? (y/n)");
			System.out.println("[Note: Entering 'y' will close the file, all unsaved data will be lost]");				
			System.out.println("Please enter y/n: ");
			String ans = scan1.nextLine();
			while(!ans.equalsIgnoreCase("y") && !ans.equalsIgnoreCase("yes"))
			{
				System.out.println("Are you done creating the input file and saving it? (y/n)");
				System.out.println("[Note: Entering 'y' will close the file, all unsaved data will be lost]");				
				System.out.println("Please enter y/n: ");
				ans = scan1.nextLine();
				if(ans.equalsIgnoreCase("y") || ans.equalsIgnoreCase("yes"))
				{
					System.out.println("Are you sure? (All unsaved data will be lost)[Press y/n]: ");
					ans = scan1.nextLine();
				}
			}								

			p.destroy();

		} catch (IOException e) {
			e.printStackTrace();
		}


		choice = graphInputOption();			
		List<String> fileDetails = processChoice(choice);
		attGraphPath = fileDetails.get(0);
		attGraphFilename = fileDetails.get(1);
		break;

		default:
			break;
		}

		// For storing the Attack Graph file path and Attack Graph filename

		List<String> attGraphfileDetails = new ArrayList<String>();		
		
			attGraphfileDetails.add(attGraphPath);
			attGraphfileDetails.add(attGraphFilename);
			attGraphfileDetails.add(choice);		
			return attGraphfileDetails;		
		
	}

}

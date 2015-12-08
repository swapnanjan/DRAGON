package driver; //Rename to lower-case all packages




//import java.io.BufferedReader;

import generate.GmlGenerator;
import generate.GraphFileGenerator;
import gml.GMLParser;

import impact_analysis.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import parser.*;

import jung.DisplayGraph;

import reasoner.AcyclicPreferenceReasoner;
import reasoner.PreferenceReasoner;
import tasks.MainTasks;
import translate.CINetToSMVTranslator;
import translate.PreferenceInputTranslator;
import tree.*;
import verify.*;



/**
 * Main class for analyzing the Attack Graph and CVSS impacts.	 
 * @author Swapnanjan Chatterjee, schatt@iastate.edu
 *
 */

public class AttackGraphMain extends ImpactAnalyzer{				


	// To-do use type List instead of ArrayList

	public static ArrayList<Node> nodes = new ArrayList<Node>();


	/**
	 * Detecting the OS path separator
	 */

	public static String sep = File.separator;


	/**
	 *	Location of the file & filename to be parsed 
	 */	
	//	public static String filename = "C:\\Users\\Swapnanjan\\Desktop\\Graphs\\Model12.txt";
	public static String attGraphFilename = "Graphs"+ sep + "Model12.txt";


	/**
	 * location of the CI-net specifying preferences over the goal model
	 */
	public static String ciNetLocn = "demoPref.cinet";

	/**
	 * @param args ignored
	 * @throws InterruptedException 
	 */
	@SuppressWarnings({ "unused" })

	public static void main(String[] args) throws InterruptedException {


		Date                  beginTime, endTime;		
		Date                  beginTreeSetUpTime, endTreeSetUpTime;
		Date                  beginAllSatTime, endAllSatTime;
		Date                  beginPrefSatTime, endPrefSatTime;
		Date                  beginDFSTime, endDFSTime;
		Date                  beginInfixTime, endInfixTime;
		Date				  beginGMLTime, endGMLTime;
		Date				  beginCVSSParseTime, endCVSSParseTime;
		
		/**
		 * An object of main task which will help call the methods
		 */
		MainTasks mt = new MainTasks();


		System.out.println("Welcome to the Attack Graph Analyzer Tool");
		System.out.println("=============================================");					

		InputOptions io = new InputOptions();
		String choice = io.graphInputOption();

		List<String> fileDetails = io.processChoice(choice);
		choice = fileDetails.get(2);

		System.out.println();
		System.out.println("=========================================================================================================================================");
		System.out.println();
		if(choice.equals("1"))
		{
			attGraphFilename = fileDetails.get(0) + sep + fileDetails.get(1);
			System.out.println("FileName: " + attGraphFilename);
		}
		else if(choice.equals("2"))
		{
			attGraphFilename = fileDetails.get(0) + sep + fileDetails.get(1) + ".txt";
			System.out.println("Filename: " + attGraphFilename);
		}


		/**
		 *	Creating Objects of VerifyPolicy for verification 
		 */

		PolicyVerifier vp = new PolicyVerifier();


		/**
		 *  Begin timing
		 */
		beginTime = new Date();


		/**
		 * Parsing the input file and setting up the Tree
		 */

		// Begin Tree Set-Up Timer

		Path filePath = Paths.get(attGraphFilename);

		if(filePath.toFile().exists())
		{
			beginTreeSetUpTime = new Date();

			TreeParser tp = new TreeParser();
			tp.parse(attGraphFilename, nodes);		
			endTreeSetUpTime = new Date();

			List<String> pnodes = tp.getPnodes();
			List<String> enodes = tp.getEnodes();
			List<String> lnodes = tp.getLnodes();

			// Creating an object of TreeValidator for validating
			TreeValidator tv = new TreeValidator();		

			/**
			 * For validating the input graph .txt file, so that it doesn't contain redundant node names
			 */			
			boolean check = tv.checkAttackGraphValidity(pnodes, enodes, lnodes);

			/**
			 * For validating the leaf nodes don't have any children
			 */

			boolean check2 = tv.checkLeafValidity(nodes);

			if(check == true && check2 == true)
			{
				System.out.println("\n=========================================================================================================================================");
				System.out.println();
				System.out.println("Successfully parsed the input attack graph file");
				System.out.println();

				System.out.println("Tree setup began: " + beginTreeSetUpTime);
				System.out.println("Tree setup ended: " + endTreeSetUpTime);
				System.out.println("Total time taken for setting up the tree: " + (endTreeSetUpTime.getTime() - beginTreeSetUpTime.getTime()) + " ms");
				System.out.println("\n=========================================================================================================================================");
				System.out.println();
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
		}
		else
		{
			System.out.println("\n=========================================================================================================================================");
			System.out.println();
			System.out.println("Unable to parse input attack graph file");
			System.err.println("Possible reason: The filename/path is incorrect");
			System.out.println("Exiting the program ...");
			System.exit(0);
		}



		/**
		 * Parsing the CVSS input File
		 */
		
		Date beginCVSSInput = new Date();
		String file = io.inputCVSS();
		Date endCVSSInput = new Date();

		// To keep track of how much time was spent by user to enter inputs and deduct it from total execution time later
		long cvssInputTime = endCVSSInput.getTime() - beginCVSSInput.getTime(); 

		if(!file.equalsIgnoreCase("null"))
		{
			beginCVSSParseTime = new Date();				
			CVSSParser cvp = new CVSSParser();
			cvp.fileParser(file, nodes);						
			endCVSSParseTime = new Date();		

			System.out.println("Successfully parsed the input CVSS file");
			System.out.println();		

			System.out.println("CVSS File Parsing began: " + beginCVSSParseTime);
			System.out.println("CVSS File Parsing ended: " + endCVSSParseTime);
			System.out.println("Time taken to parse CVSS input file: " + (endCVSSParseTime.getTime() - beginCVSSParseTime.getTime()) + " ms");
			System.out.println("\n=========================================================================================================================================");
			System.out.println();
		}
		else
		{
			System.out.println("Unable to parse CVSS input file");
			System.out.println("Possible reason: The filename/path is incorrect");
			System.out.println("Exiting the program ...");
			System.exit(0);
		}



		/**
		 * Displaying the graph using Jung
		 * Uncomment the following lines to see the JUNG output
		 */

		//		DisplayGraph dg = new DisplayGraph();
		//		dg.displayGraph(nodes);


		/**
		 * Generating GML file and opening Y-ed.exe to display it
		 */



		String modelName = attGraphFilename.substring(attGraphFilename.lastIndexOf(sep)+1, attGraphFilename.lastIndexOf("."));

		if(!choice.equals("2"))
		{
			beginGMLTime = new Date();
			GmlGenerator gml = new GmlGenerator();
			boolean checkGML = gml.generateGML(nodes, modelName);

			if(checkGML == true)
			{
				System.out.println("Successfully created the GML file");
				try {
					Process p = Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + "GML" + sep + modelName + ".gml" );

				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			else
				System.err.print("Unable to generate the required GML file!!\n");

			endGMLTime = new Date();
			System.out.println();
			System.out.println("GML file generation started: " + beginGMLTime);
			System.out.println("GML file generation ended: " + endGMLTime);
			System.out.println("Time taken to create file and display: " + (endGMLTime.getTime()- beginGMLTime.getTime()) + " ms");
			System.out.println("\n=========================================================================================================================================");
			System.out.println();
		}	




		/**
		 * Print data about the Tree
		 */

		mt.printTree(nodes);
		
		System.out.println("\n=========================================================================================================================================");
		System.out.println();
				

		/**	
		 * Creating an Object of class Traverse for performing DFS and Infix traversal
		 */

		TreeTraversor traverse = new TreeTraversor();

		/**
		 * 	Print the Nodes in Depth First Traversal order 
		 */
		System.out.println("DFS Traversal:");
		System.out.println("===================");

		beginDFSTime = new Date();		

		traverse.dfs(nodes);

		endDFSTime = new Date();		
		System.out.println("DFS Traversal began: " + beginDFSTime);
		System.out.println("DFS Traversal ended: " + endDFSTime);
		System.out.println("Total time taken for DFS traversal: " + (endDFSTime.getTime() - beginDFSTime.getTime()) + " ms");
		System.out.println("\n=========================================================================================================================================");		
		System.out.println();

		/**
		 * Print the Nodes Infix Traversal 
		 */

		System.out.println("Infix Traversal:");
		System.out.println("===================");

		beginInfixTime = new Date();

		traverse.infix(nodes);

		endInfixTime = new Date();		
		System.out.println("\nInfix Traversal began: " + beginInfixTime);
		System.out.println("Infix Traversal ended: " + endInfixTime);
		System.out.println("Total time taken for Infix traversal: " + (endInfixTime.getTime() - beginInfixTime.getTime()) + " ms");
		System.out.println("\n=========================================================================================================================================");		
		System.out.println();


		endTime = new Date();
		//		long tempTime = endTime.getTime() - beginTime.getTime();		
		Date actualBeginTime = (Date)beginTime.clone();		


		// ** End timing and print time elapsed **		
		endTime = new Date();
		System.out.println("Statistics of this execution cycle");
		System.out.println("-----------------------------------------------");
		System.out.println();
		System.out.println("Execution began: " + beginTime.toString());
		System.out.println("Execution ended: " + endTime.toString());
		System.out.print("Total execution time: ");
		System.out.print(endTime.getTime() - (beginTime.getTime() + cvssInputTime));
		System.out.print(" ms");		
		long tempTime = endTime.getTime() - (beginTime.getTime() + cvssInputTime);
		System.out.println("\n=========================================================================================================================================");
		System.out.println("\n############################################################################");
		System.out.println("\n=========================================================================================================================================");
		System.out.println();



		/**
		 * This part for the defender's perspective
		 */

		System.out.println("\nThe Satisfiability from defender's perspective:");
		System.out.println("==================================================");	
				

		/**
		 * Inputing the filename and location of the file containing CVSS preference order
		 */
		file = io.inputCVSSPreferences();


		if(!file.equalsIgnoreCase("null"))
		{
			/**
			 * Calling the method as a lot of tasks need to be performed and Main() will be too long
			 */
			mt.analyseDefenderPolicy(file, nodes);
		}
		else
		{
			System.out.println("Unable to parse CIA Preferred input file");
			System.out.println("Possible reason: The filename/path is incorrect");
			System.out.println("Exiting the program ...");
			System.exit(0);
		}	
		return;
	}

}

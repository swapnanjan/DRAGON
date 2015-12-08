package tasks;

import impact_analysis.ImpactAnalyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Scanner;

import parser.CVSSPreferenceParser;
import tree.CVSS;
import tree.Node;

public class MainTasks {
	
	/**
	 * A method to print the details about the Attack Graph like: the names of the Privilege nodes, Exploit nodes and Configuration/Fact nodes.
	 * @param nodes is an ArrayList<Node> that contains the details about the structure of the input attack graph.
	 */
	public void printTree(ArrayList<Node> nodes)
	{
		int tempCounter = 1;

		System.out.println("Priviledge Nodes:");
		System.out.println("======================");
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 1)
				System.out.println(tempCounter++ + ") " + nodes.get(i).getName());
		}
		System.out.println();

		tempCounter = 1;
		System.out.println("Exploit Nodes:");
		System.out.println("======================");
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 2)
				System.out.println(tempCounter++ + ") " + nodes.get(i).getName());
		}
		System.out.println();

		tempCounter = 1;
		System.out.println("Configuration Nodes:");
		System.out.println("======================");
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 0)
				System.out.println(tempCounter++ + ") " + nodes.get(i).getName());
		}		

	}

	/**
	 * A method to help analyze the defender policy, by first forming a data-structure of the <C,I,A> preferred valuations,
	 * then analyzing whether each of those <C,I,A> valuations can yield a valid defense policy.    
	 * @param file is the file-path + file-name of file containing the input for forming the data-structure.
	 * @param nodes is the ArrayList<Node> that contains the structure of the input attack graph.
	 */
	
	public void analyseDefenderPolicy(String file, ArrayList<Node> nodes)
	{

		Date beginTime, endTime; 

		
		/**
		 * Creating object of Impact Analyzer
		 */
		ImpactAnalyzer ia = new ImpactAnalyzer();
		
		
		/**
		 * Creating object of CVSSPreferenceParse
		 */		
		CVSSPreferenceParser cpp = new CVSSPreferenceParser();


		/**
		 * Creating a list of CVSS objects to store these <C,I,A> valuations		 
		 */
		ArrayList<CVSS> cvss_values = new ArrayList<CVSS>();

		/**
		 * An ArrayList<ArrayList<Integer>> for storing the preferred order of <C,I,A> values
		 */		
		ArrayList<ArrayList<Integer>> preferences = cpp.parsePreference(file);

		for(ArrayList<Integer> cia : preferences)
		{
			int c = cia.get(0);
			int i = cia.get(1);
			int a = cia.get(2);
			cvss_values.add(new CVSS(c, i, a));
		}

		for(int i=0; i<cvss_values.size(); i++)
		{
			System.out.println("-----------------------------------------------------");
			System.out.println(i+1 + ") Input <C,I,A>: <" + cvss_values.get(i).getC() + ", " + cvss_values.get(i).getI() + ", " + cvss_values.get(i).getA() + ">" );
			System.out.println("-----------------------------------------------------");
			beginTime = new Date();		
			ia.analyze(cvss_values.get(i).getC(), cvss_values.get(i).getI(), cvss_values.get(i).getA(), nodes);		
			endTime = new Date();

			System.out.println("Execution began: " + beginTime.toString());
			System.out.println("Execution ended: " + endTime.toString());				
			System.out.print("Total execution time: ");
			System.out.print(endTime.getTime() - beginTime.getTime());
			System.out.print(" ms");
			System.out.println();
			System.out.println("**********************************************************************************************************************************************");
			System.out.println();
			if(i < cvss_values.size()-1)
				System.out.println("Press Enter to continue with next preferred valuation ...");
			else
				break;
			
			Scanner scan = new Scanner(System.in);
			String input = scan.nextLine();
			if(input.equals(""))
				continue;
			else
			{
			try {
				while (System.in.available() == 0){
					//Waiting for "Enter" hit by the user
				}
			} catch (IOException e) {
				System.out.println("The program encountered and error");
				e.printStackTrace();
				System.out.println("Exiting the program...");
				System.exit(0);				
			}										
			continue;
			}
			}												

	
	}
}

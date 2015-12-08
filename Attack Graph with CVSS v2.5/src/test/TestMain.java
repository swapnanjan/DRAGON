package test;

import generate.CVSSFileGenerator;
import generate.ImpactMetricsAnalyzer;

import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Scanner;

import tree.Node;

public class TestMain {

	/**
	 * A central testing center for performing various analysis and test scenarios.
	 */
	public static void main(String[] args) {
				
		
		/**
		 * Generate any number of random test CVSS files for each model inside the Graphs Folder
		 */
/*		
		Scanner scan = new Scanner(System.in);
		System.out.println("Enter no. of files to generate: ");
		String input = scan.nextLine();
		int fileCount = Integer.parseInt(input);
		
		String graphDir = "C:\\Users\\Swapnanjan\\Desktop\\Graphs\\";
		CVSSFileGenerator cfg  = new CVSSFileGenerator();
		boolean check = cfg.generateFiles(graphDir, fileCount);
		if(check == true)
			System.out.println("Succesfully created all the Test Files!");
		else
			System.out.println("There was a problem generating the files !");
		
		System.out.println();
		System.out.println("================================================================================");
		System.out.println();
		
*/				
		ArrayList<Node> nodes = new ArrayList<Node>(); 
		
		
		String modelFileDir = "C:\\Users\\Swapnanjan\\Desktop\\Graphs\\";
		String modelFileName = "Demo_Model2";
		
		/**
		 * Creating the output Directory to store output files
		 */
		String dirName = "Output";
		File directory = new File(dirName);
		directory.mkdir();
				
		System.out.println("Enter no. of analysis tests to run (1-216): ");
		Scanner scan = new Scanner(System.in);
		String input = scan.nextLine();		
//		input = scan.nextLine();
		int tests = 216;	//Default number of analysis to perform
		tests = Integer.parseInt(input);
		while(tests < 1 || tests > 216)
		{
			if(tests < 1)
				System.out.println("Number of tests cannot be less than 1!");
			if(tests > 216)
				System.out.println(tests + " exceeds the possible number of tests!");
			
			System.out.println("Enter no. of analysis tests to run (1-216): ");
			input = scan.nextLine();		
			tests = Integer.parseInt(input);
		}
		scan.close();
		
		ImpactMetricsAnalyzer ga = new ImpactMetricsAnalyzer();
		boolean check1 = ga.analyseCVSS(nodes, modelFileDir+modelFileName+".txt", modelFileName, tests);			
				
		if(check1 == true)
			System.out.println("Successfully finished all tasks!!!");
		else
			System.out.println("There was a problem with the requested tasks !");
	

	}

}

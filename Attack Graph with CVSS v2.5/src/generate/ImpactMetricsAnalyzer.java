package generate;

import impact_analysis.ImpactAnalyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;

import parser.CVSSParser;
import parser.TreeParser;
import tree.Node;


public class ImpactMetricsAnalyzer {

	/**
	 * A method that calls the ImpactAnalyzer and then writes the analysis to an output file.
	 * @param nodes is the ArrayList<Node> that contains information about the entire stricture of the attack graph.
	 * @param filePath is the file-path of the input attack graph file.
	 * @param modelName is the name of the input attack graph model under analysis.
	 * @param numberOfAnalysis is the total number of analysis to be performed.
	 * @return true, if the output file was successfully created, else return false.
	 */
	public boolean analyseCVSS(ArrayList<Node> nodes, String filePath, String modelName, int numberOfAnalysis)
	{				
		/**
		 * Analyzing the generated test files for each model
		 */		

		String testDir = "TestFile\\";
		File inputTestDir = new File(testDir + modelName + "_test");							
		File[] listOfFiles = inputTestDir.listFiles();

		/**
		 * Creating the Output Folder for storing all the output result files for the model
		 */

		String outputDirName = "Output\\Output_"+modelName;
		File outputDirectory = new File(outputDirName);
		outputDirectory.mkdir();

		for(File file: outputDirectory.listFiles())
			file.delete();


		/**
		 * Parsing the Tree input
		 */
		TreeParser tp = new TreeParser();		
		tp.parse(filePath, nodes);
		
		/**
		 * Storing the console output as the default output
		 */
		PrintStream orgStream = System.out;


		for(int i=1; i<=listOfFiles.length; i++)
		{

			/**
			 * Keeping Track of the <C,I,A> inputs already used
			 */
			
			HashSet<ArrayList<Integer>> usedCIA = new LinkedHashSet<ArrayList<Integer>>();												
			try {
				/**
				 * Setting the output stream to the text file
				 */				
				PrintStream	out = new PrintStream(new FileOutputStream(outputDirName + "\\output_test" + i + ".txt"));
				System.setOut(out);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				return false;
			}
			System.out.println("Analysing input file: test" + i + ".txt");
			System.out.println("=====================================================");
			System.out.println();
								

			/**
			 * Re-setting the C,I,A values for each node in the model
			 */

			for(int j=0; j<nodes.size(); j++)
			{
				nodes.get(j).setImpacts(7, 7, 7);
			}


			/**
			 * Parsing the test file(s) 1 at a time
			 */			

			CVSSParser cvp = new CVSSParser();
			cvp.fileParser(testDir+modelName+"_test\\test" + i +".txt", nodes);

			/**
			 * Performing the analysis based on that file
			 */
			int r = 0;
			while(usedCIA.size() < numberOfAnalysis)
			{
				ArrayList<Integer> tempList = new ArrayList<Integer>();
				ImpactAnalyzer ia = new ImpactAnalyzer();
				
				int c_val = 1 + (int)(Math.random()*6);
				int i_val = 1 + (int)(Math.random()*6);
				int a_val = 1 + (int)(Math.random()*6);
			
				
				tempList.add(c_val);
				tempList.add(i_val);
				tempList.add(a_val);
								
				if(usedCIA.contains(new ArrayList<Integer>(tempList)))
				{					
					continue;
				}				
				
				usedCIA.add(new ArrayList<Integer>(tempList));									
				
				System.out.println();
				System.out.println("*******************************************************************************************************************************");
				System.out.println("------------------------------------------------------------------------------------");
				System.out.println((r+1) + ") Performing analysis for <C,I,A>: <" + c_val + ", " + i_val + ", " + a_val + ">");
				System.out.println("------------------------------------------------------------------------------------");
				ia.analyze(tempList.get(0), tempList.get(1), tempList.get(2), nodes);												
				r++;
			}		

			usedCIA.clear();			
		}	
		/*	Re-setting the output Stream to the console	*/
		System.setOut(orgStream);		
		return true;
	}
}

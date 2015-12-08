package test;

import generate.AttackGraphGenerator;
import generate.AttackGraphGenerator;
import generate.GmlGenerator;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

import tree.Node;

public class TestAttackGraphGenerator {
	
	/**
	 * Main method to generate random attack graphs based on user inputs.	 
	 */
	
	public static void main(String[] args) {
					
		Scanner scan = new Scanner(System.in);
		System.out.println("Enter the approximate number of nodes you want in the graph: ");		
		String input = scan.nextLine();
		System.out.println("Enter the max. out-degree of each node: ");		
		String input2 = scan.nextLine();				
		int node_count = 0;
		int degree = 0;
		try{
			node_count = Integer.parseInt(input);
			degree = Integer.parseInt(input2);			
			while(node_count < 3 || node_count <= degree || degree<=0)
			{
				System.out.println("Invalid entry!!");
				System.out.println("Enter the approximate number of nodes you want in the graph: ");		
				input = scan.nextLine();
				System.out.println("Enter the max. out-degree of each node: ");		
				input2 = scan.nextLine();
				node_count = Integer.parseInt(input);
				degree = Integer.parseInt(input2);	
			}
		}catch(Exception e){
			System.out.println("There was an error parsing the inputs!");
			System.out.println("Cannot convert to integer values. " + e);
		}
		
		AttackGraphGenerator agg = new AttackGraphGenerator();
		ArrayList<Node> nodes = agg.generateAttackGraph(node_count, degree);
		
		
		String modelName = "Test(Graph_Swap)";
		GmlGenerator gml = new GmlGenerator();
		boolean checkGML = gml.generateGML(nodes, modelName);

		if(checkGML == true)
		{
			System.out.println("Successfully created the GML file");
			try {
				Process p = Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + "GML" + File.separator + modelName + ".gml" );

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else
			System.err.print("Unable to generate the required GML file!!\n");

		
	}

}

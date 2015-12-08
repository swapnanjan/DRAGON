package test;

import generate.GraphFileGenerator;
import gml.*;

import java.awt.List;
import java.util.ArrayList;
import java.util.Scanner;

import tree.Node;


public class TestGMLParser {

	/**
	 * A method to test the GML parser.
	 */
	public static void main(String[] args) {

		GMLParser gp = new GMLParser();
		
		String path = "GML";
		String fileName = "Model(Swap1).gml";
		
		ArrayList<Node> nodes = gp.parseGML(path, fileName);
		
		System.out.println("The Nodes:");
		for(int i=0; i<nodes.size(); i++)
		{
			System.out.println("Name: " + nodes.get(i).getName() + "Type: " + nodes.get(i).getType());
			System.out.println("Parent: ");
			for(int j=0; j<nodes.get(i).getParents().size(); j++)
			{
				System.out.println(nodes.get(i).getParents().get(j).getName());
			}
//			System.out.println("Children: ");
			for(int j=0; j<nodes.get(i).getChildren().size(); j++)
			{
				System.out.println(nodes.get(i).getChildren().get(j).getName());
			}					
		}
		
		Scanner scan = new Scanner(System.in);
		System.out.println("\nEnter the name of this Model: ");
		String modelName = scan.nextLine();
		
		GraphFileGenerator gfg = new GraphFileGenerator();
		gfg.generateGraph(nodes, modelName);

	}

}

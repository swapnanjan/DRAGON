package test;

import impact_analysis.ImpactAnalyzer;

import java.util.ArrayList;

import tree.Node;




public class TestCVSS extends ImpactAnalyzer{

	/**
	 * A method to test the CVSS analysis engine.
	 */
	public static void main(String[] args) {


		ArrayList<Node> N = new ArrayList<Node>();
		
		/*
		 * ##### Encoding Model 2 ###### 
		 */
		
		
		/*
		 * Encoding the privilege nodes
		 */
		for(int i=1; i<7; i++)
		{
			N.add(new Node("p"+i, 1));
		}
		
		/*
		 * Encoding the exploit nodes		 
		 */
		for(int i=1; i<8; i++)
		{
			N.add(new Node("e"+i, 2));
		}
		
		/*
		 * Encoding the child nodes
		 */
		for(int i=1; i<12; i++)
		{
			N.add(new Node("c"+i, 0));
		}
		
		/*
		 * Assigning the children and parent(s) for each node according to model 2
		 */
		
		ArrayList<Node> nil = new ArrayList<Node>();
		
		N.get(0).setParents(nil);
		N.get(0).addChild(N.get(6));
		
		N.get(6).addParent(N.get(0));
		N.get(6).addChild(N.get(1));
		N.get(6).addChild(N.get(13));
		N.get(6).addChild(N.get(14));
		
		N.get(1).addParent(N.get(6));
		N.get(1).addChild(N.get(7));
		N.get(1).addChild(N.get(8));
		
		N.get(7).addParent(N.get(1));
		N.get(7).addChild(N.get(15));
		N.get(7).addChild(N.get(2));
		
		N.get(2).addParent(N.get(7));
		N.get(2).addChild(N.get(10));		
		
		N.get(8).addParent(N.get(1));
		N.get(8).addChild(N.get(16));
		N.get(8).addChild(N.get(3));
		
		N.get(3).addParent(N.get(8));
		N.get(3).addChild(N.get(9));
		
		N.get(10).addParent(N.get(2));
		N.get(10).addChild(N.get(5));
		N.get(10).addChild(N.get(19));
		N.get(10).addChild(N.get(20));
		
		N.get(9).addParent(N.get(3));
		N.get(9).addChild(N.get(4));
		N.get(9).addChild(N.get(17));
		N.get(9).addChild(N.get(18));
		
		N.get(4).addParent(N.get(9));
		N.get(4).addChild(N.get(12));
		
		N.get(5).addParent(N.get(10));
		N.get(5).addChild(N.get(11));
		
		N.get(12).addParent(N.get(4));
		N.get(12).addChild(N.get(22));
		N.get(12).addChild(N.get(23));
		
		N.get(11).addParent(N.get(5));
		N.get(11).addChild(N.get(21));
		N.get(11).addChild(N.get(23));
		
		N.get(13).addParent(N.get(6));
		N.get(14).addParent(N.get(6));
		N.get(15).addParent(N.get(7));
		N.get(16).addParent(N.get(8));
		N.get(17).addParent(N.get(9));
		N.get(18).addParent(N.get(9));
		N.get(19).addParent(N.get(10));
		N.get(20).addParent(N.get(10));
		N.get(21).addParent(N.get(11));
		N.get(22).addParent(N.get(12));
		N.get(23).addParent(N.get(11));
		N.get(23).addParent(N.get(12));
		
		
		/*
		 * Encoding the C,I,A values for each node
		 */
		
		N.get(0).setImpacts(4, 4, 4);
		N.get(1).setImpacts(1, 2, 3);
		N.get(2).setImpacts(2, 2, 1);
		N.get(3).setImpacts(1, 2, 1);
		N.get(4).setImpacts(1, 1, 1);
		N.get(5).setImpacts(3, 2, 3);
		N.get(13).setImpacts(3,3,3);
		N.get(14).setImpacts(3,3,3);
		N.get(15).setImpacts(3,3,3);
		N.get(16).setImpacts(3,3,3);
		N.get(17).setImpacts(3,3,3);
		N.get(18).setImpacts(3,3,3);
		N.get(19).setImpacts(3,3,3);
		N.get(20).setImpacts(3,3,3);
		N.get(21).setImpacts(3,3,3);
		N.get(22).setImpacts(3,3,3);
		N.get(23).setImpacts(2,2,1);
		
		
		
		
		
		/*
		 * This block helps see the setup of the whole tree. 
		 * Comment out if not required to see the parent children relationship of each node.
		 */
		
		for(int i=0; i<24; i++)
		{
			System.out.println("\n\n" + N.get(i).getName() + " < C=" + N.get(i).getImpactC() + ", I=" + N.get(i).getImpactI() + ", A=" + N.get(i).getImpactA() + " >" );
			System.out.println("Parents: ");
			for(int j=0; j<N.get(i).getParents().size(); j++)
			{
				System.out.print(N.get(i).getParents().get(j).getName() + "  ");
			}
			System.out.println("\nChildren: ");
			for(int k=0; k<N.get(i).getChildren().size(); k++)
			{
				System.out.print(N.get(i).getChildren().get(k).getName() + "  ");
			}
		}
		
		
		/*
		 * Calling the method which will perform the C,I,A impact analysis 
		 */
		
		//Node n = new Node(); //Commented out as extended Main to Node and declared impactAnalysis() as static 
		
		ImpactAnalyzer ia = new ImpactAnalyzer();
		ia.analyze(2, 2, 1, N);
		
		
		
	}

}

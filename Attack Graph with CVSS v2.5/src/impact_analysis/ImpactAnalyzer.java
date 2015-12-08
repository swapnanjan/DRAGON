package impact_analysis;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import tree.Node;


public class ImpactAnalyzer extends Node {


	/**
	 * A method to compute union over the intersection of 3 sets at a time.
	 * The if conditions check that the set added to the union is not empty.
	 * @param set1 is a set of node names.
	 * @param set2 is a set of node names.
	 * @param set3 is a set of node names.
	 * @param set4 is a set of node names.
	 * @param set5 is a set of node names.
	 * @param set6 is a set of node names.
	 * @param set7 is a set of node names.
	 * @return union is a HashSet<HashSet<String>> containing the union set of the input sets
	 */

	public static HashSet<HashSet<String>> UnionOfSets(HashSet<String> set1, HashSet<String> set2, HashSet<String> set3, HashSet<String> set4, HashSet<String> set5, HashSet<String> set6, HashSet<String> set7)
	{
		HashSet<HashSet<String>> union = new LinkedHashSet<HashSet<String>>();
		if(set1.size() != 0)
			union.add(set1);
		if(set2.size() != 0)
			union.add(set2);
		if(set3.size() != 0)
			union.add(set3);
		if(set4.size() != 0)
			union.add(set4);
		if(set5.size() != 0)
			union.add(set5);
		if(set6.size() != 0)
			union.add(set6);
		if(set7.size() != 0)
			union.add(set7);		

		return union;

	}


	/**
	 * A method to compute intersection of 3 sets.
	 * @param set 1 is a set of node names.
	 * @param set 2 is a set of node names.
	 * @param set 3 is a set of node names.
	 */

	public static HashSet<String> intersectionOfSets(HashSet<String> set1, HashSet<String> set2, HashSet<String> set3) {

		HashSet<String> intersection = new LinkedHashSet<String>();


		/*
		 * The if logic helps identify the smallest of the 3 sets.
		 * Then checks if the elements present in it are present in the other 2 sets as well.
		 */
		if(set1.size() <= set2.size() && set1.size() <= set3.size())
		{
			for (String p : set1) 
			{
				if (set2.contains(p) && set3.contains(p)) { 
					intersection.add(p);
				}
			}
		}
		if(set2.size() <= set1.size() && set2.size() <= set3.size())
		{
			for (String p : set2) 
			{
				if (set1.contains(p) && set3.contains(p)) {                
					intersection.add(p);
				}
			}        	
		}
		if(set3.size() <= set1.size() && set3.size() <= set2.size())
		{
			for (String p : set3) 
			{
				if (set1.contains(p) && set2.contains(p)) {                
					intersection.add(p);
				}
			}        	
		}
		return intersection;
	}




	/**
	 * The method to compute an exact set and a better set based on the input CVSS valuations.
	 * @param C_input is the input valuation for Confidentiality Impact.
	 * @param I_input is the input valuation for Integrity Impact.
	 * @param A_input is the input valuation for Availability Impact.
	 * @param nodes is the ArrayList<Node> that contains information about the structure of the attack graph.
	 * @return prefPairs is a List<Set<String>> that contains the set of exacts and better based on the input.   
	 */

	public List<Set<String>> preProcess(int C_input, int I_input, int A_input, ArrayList<Node> nodes)
	{


		HashSet<String> exactCandidates = new LinkedHashSet<String>();		

		/*
		 * Categorize all the nodes into Sets of exact C, I, A values and better  
		 */

		HashSet<String> exact_C = new LinkedHashSet<String>(); 
		HashSet<String> better_C = new LinkedHashSet<String>();				
		HashSet<String> exact_I = new LinkedHashSet<String>();
		HashSet<String> better_I = new LinkedHashSet<String>();
		HashSet<String> exact_A = new LinkedHashSet<String>();
		HashSet<String> better_A = new LinkedHashSet<String>();

		/*
		 * This for loop and if blocks adds the exact match for C,I,A values or better to the corresponding sets
		 */
		for(int i=0; i<nodes.size(); i++)
		{
			//			System.out.println("Node["+i+"]= "+nodes.get(i).getName() + "<C,I,A>= " + nodes.get(i).getImpactC()+", "+ nodes.get(i).getImpactI()+", "+ nodes.get(i).getImpactA());
			if(nodes.get(i).getType() == 1 || nodes.get(i).getType() == 0)
			{
				if(nodes.get(i).getImpactC() == C_input)				
					exact_C.add(nodes.get(i).getName());				
				if(nodes.get(i).getImpactC() < C_input)
					better_C.add(nodes.get(i).getName());
				if(nodes.get(i).getImpactI() == I_input)				
					exact_I.add(nodes.get(i).getName());				
				if(nodes.get(i).getImpactI() < I_input)
					better_I.add(nodes.get(i).getName());
				if(nodes.get(i).getImpactA() == A_input)				
					exact_A.add(nodes.get(i).getName());				
				if(nodes.get(i).getImpactA() < A_input)
					better_A.add(nodes.get(i).getName());					
			}
		}

		/*
		 * Print the sets of exact and better C,I,A values.
		 */
		System.out.println("\nThe exact set of Nodes that matches C_input: " + exact_C);		
		System.out.println("\nThe set of Nodes that are better than C_input: " + better_C);		
		System.out.println("\nThe exact set of Nodes that matches I_input: " + exact_I);		
		System.out.println("\nThe set of Nodes that are better than I_input: " + better_I);		
		System.out.println("\nThe exact set of Nodes that matches A_input: " + exact_A);		
		System.out.println("\nThe set of Nodes that are better than A_input: " + better_A);		

		/*
		 * Finding the candidates who are in the intersection of the exact sets of C,I,A values
		 */
		exactCandidates = intersectionOfSets(exact_C, exact_I, exact_A);
		System.out.println("\nThe intersection exact set of Nodes that matches C_input, I_input and A_input: " + exactCandidates);

		/*
		 * Finding all other candidates who might be better than the supplied C,I,A values but not exact matches 
		 */
		HashSet<HashSet<String>> betterCandidatesTemp = UnionOfSets(intersectionOfSets(exact_C, exact_I, better_A), intersectionOfSets(exact_C, better_I, exact_A), intersectionOfSets(exact_C, better_I, better_A), intersectionOfSets(better_C, exact_I, exact_A), intersectionOfSets(better_C, exact_I, better_A), intersectionOfSets(better_C, better_I, exact_A), intersectionOfSets(better_C, better_I, better_A));
		System.out.println("\nThe union of Nodes that matches combinations of better C, I and A values: " + betterCandidatesTemp);

		/*
		 * Converting from HashSet<HashSet<String>> to HashSet<String before calling the analyzer
		 */

		ArrayList<String> tempSet = new ArrayList<String>();
		for(HashSet<String> set : betterCandidatesTemp)
		{
			for(String elements : set)
			{
				tempSet.add(elements);
			}
		}

		HashSet<String> betterCandidates = new LinkedHashSet<String>(tempSet); 		

		List<Set<String>> prefPairs = new ArrayList<Set<String>>();		
		prefPairs.add(betterCandidates);
		prefPairs.add(exactCandidates);

		return prefPairs;
	}

	/**
	 * A method to analyze the CVSS impacts.
	 * @param C_input is the input valuation for Confidentiality Impact to be measured.
	 * @param I_input is the input valuation for Integrity Impact to be measured.
	 * @param A_input is the input valuation for Availability Impact to be measured.
	 * @param nodes is the ArrayList<Node> that contains information about the structure of the attack graph.
	 */
	@SuppressWarnings("static-access")
	public void analyze(int C_input, int I_input, int A_input, ArrayList<Node> nodes)
	{
		List<Set<String>> prefPairs = preProcess(C_input, I_input, A_input, nodes);
		PolicyGenerator npg = new PolicyGenerator();
		
		int iterations = 1;

		Date	startBottomUpTime, endBottomUpTime;
		Date	startTopDownTime, endTopDownTime;
		Date	startVerifierTime, endVerifierTime;
		
		
		startBottomUpTime = new Date();
		/**
		 *  ##################   Performing Bottom-Up Analysis #############
		 */
				
		ArrayList<String> policy = npg.bottomUp(prefPairs.get(0), prefPairs.get(1));
		System.out.println("\nPolicy: " + policy);

		startVerifierTime = new Date();
		boolean check = verifyDefence(policy, nodes);
		endVerifierTime = new Date();		
		System.out.println();		
		System.out.println("Time Taken for verifying the policy: " + (endVerifierTime.getTime() - startVerifierTime.getTime()) + " ms");		
		System.out.println();
		
		if(check == true && (prefPairs.get(1).size() != 0))
		{
			System.out.println("Policy exists: Yes");
			iterations = npg.bottomUpHelper(policy, check, nodes, 1);
		}
		else
		{
			System.out.println("Policy exists: No");
			System.out.println("This is an invalid policy !!");
			System.out.println("--------------------------------------------------------------------------------------------------");
			System.out.println();
		}



		endBottomUpTime = new Date();
		System.out.println("Time taken for analysing Bottom-Up: " + (endBottomUpTime.getTime()-startBottomUpTime.getTime()) + " ms");
		System.out.println();
		System.out.println("No. of iterations: " + iterations);  
		System.out.println("\n####################################################################################################");

		/**
		 *  #######################  End of Bottom-Up Analysis #######################
		 */
		
		startTopDownTime = new Date();
		
		/**
		 *  ###################### Performing Top-Down Analysis #######################
		 */
		
		policy = npg.topDown(prefPairs.get(0), prefPairs.get(1));
		System.out.println("\nPolicy: " + policy);

		startVerifierTime = new Date();
		check = verifyDefence(policy, nodes);
		endVerifierTime = new Date();		
		System.out.println();		
		System.out.println("Time Taken for verifying the policy: " + (endVerifierTime.getTime() - startVerifierTime.getTime()) + " ms");		
		System.out.println();

		if(check == true && (prefPairs.get(1).size() != 0))
		{			
			iterations = npg.topDownHelper(policy, check, nodes, 1);
		}
		else
		{
			System.out.println("This is an invalid policy !!");
			System.out.println("--------------------------------------------------------------------------------------------------");
			System.out.println();
		}
		
		
		endTopDownTime = new Date();
		System.out.println("Time taken for analysing Top-Down: " + (endTopDownTime.getTime()-startTopDownTime.getTime()) + " ms");
		System.out.println();
		System.out.println("No. of iterations: " + iterations);
		System.out.println("\n####################################################################################################");
		
		/**
		 * ############################# End of Top-Down Analysis #########################
		 */
		
	}

}

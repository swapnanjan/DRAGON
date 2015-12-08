package impact_analysis;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import verify.PolicyVerifier;
import tree.Node;


public class PolicyGenerator extends PolicyVerifier {

	/**
	 * Stores all the combinations of the original super-policy.	 
	 */

	public static List<ArrayList<String>> allCombination = new ArrayList<ArrayList<String>>();

	/**
	 * Stores all the combinations of the original super-policy that have been already visited.	 
	 */

	public static Set<ArrayList<String>> markedCombinations = new LinkedHashSet<ArrayList<String>>();


	/**
	 * Stores the sub-set combinations of a policy on each pass dynamically.
	 * Helps localize the search.
	 */

	public static ArrayList<ArrayList<String>> combination = new ArrayList<ArrayList<String>>();


	/**
	 * Stores the original super-policy
	 */
	private static ArrayList<String> originalPolicy;

	/**
	 * Stores the original exact set of the original super-policy.	 
	 */

	private static  ArrayList<String> exactSet;


	/**
	 * Method to set the original policy
	 * @param policy is an ArrayList<String> which will be set as the original super-policy.	 
	 */

	@SuppressWarnings("unchecked")
	public static void setOriginalPolicy(ArrayList<String> policy)
	{
		originalPolicy = (ArrayList<String>)policy.clone();
	}

	/**
	 * Method to get the original policy
	 * @return originalPolicy is an ArrayList<String> which is the original super-policy.	 
	 */

	public static ArrayList<String> getOriginalPolicy()
	{
		return originalPolicy;
	}

	/**
	 * Method to reset all the sets and lists containing any combinations
	 */

	public static void reset()
	{
		combination = new ArrayList<ArrayList<String>>();
		allCombination = new ArrayList<ArrayList<String>>();
		markedCombinations = new LinkedHashSet<ArrayList<String>>();
		originalPolicy = new ArrayList<String>();
		exactSet = new ArrayList<String>();
	}

	/**
	 * Method to set the exactSet passed with the original super-policy.
	 * @param exacts is an ArrayList<String> which will be set as the exactSet of the original super-policy.	 
	 */

	@SuppressWarnings("unchecked")
	public static void setExactSet(ArrayList<String> exacts)
	{
		exactSet = (ArrayList<String>)exacts.clone();
	}

	/**
	 * Method to return the exactSet of the original super-policy.
	 * @return exactSet of type ArrayList<String>
	 */

	public static ArrayList<String> getExactSet()
	{
		return exactSet;
	}

	/**
	 * Main method to use the bottom-up analyzer of analysis for CVSS impact performance.
	 * @param betterCandidates is a HashSet<String> that contains the set of all nodes with better CVSS impact values than the input.
	 * @param exactCandidates is a HashSet<String> that has the set of all exact matches to the Preference-reasoner CVSS impact metric	 
	 */

	public static ArrayList<String> bottomUp(Set<String> betterCandidates, Set<String> exactCandidates) 
	{		

		/**
		 * Re-setting all variables
		 */
		
		reset();
		
		System.out.println("\nPerforming Bottom-Up Analysis:");
		System.out.println("===================================");
		
		HashSet<String> allCandidates = new LinkedHashSet<String>(exactCandidates);
		for(String s : betterCandidates)
			allCandidates.add(s);		

		ArrayList<String> policy = new ArrayList<String>();			

		for(String elements : allCandidates)
		{
			policy.add(elements);				
		}	

		if(!markedCombinations.contains(policy))		
			markedCombinations.add(new ArrayList<String>(policy));
		//		System.out.println("Marked Comb: " + markedCombinations);


		/*
		 * Things to perform on first pass to set up initial values and save them for later.
		 */
		ArrayList<String> exacts = new ArrayList<String>();				

		for(String s : exactCandidates)
		{
			exacts.add(s);				
		}

		setExactSet(exacts);
		setOriginalPolicy(policy);								

		return policy;		

	}
	
	/**
	 * A method to help with the bottom-up analysis.
	 * @param policy is the defense policy to be verified.
	 * @param check is true if the policy is valid, else false.
	 * @param nodes is the ArrayList<Node> that contains information about the structure of the attack graph.
	 * @return pass which is of type int and records the number of iterations 
	 */
	public int bottomUpHelper(ArrayList<String> policy, boolean check, ArrayList<Node> nodes, int pass)
	{		
		Date	startVerifierTime, endVerifierTime;

		System.out.println("This is a valid policy");
		System.out.println("--------------------------------------------------------------------------------------------------");
		System.out.println();
		
		for(int i=0; i<policy.size(); i++)
		{
			generateCombination(policy, policy.size(), policy.size()-i);							
		}
		allCombination = new ArrayList<ArrayList<String>>(combination);
//#allComb to test//						System.out.println("All Combinations: " + npg.allCombination);
		combination.clear();
		
		while(markedCombinations.size() < allCombination.size())
		{					
			/**
			 * On all subsequent passes, generate combinations of the sub-set of the sub-set of the policy just verified.				
			 */
			
			combination.clear();
			generateCombination(policy, policy.size(), policy.size()-1);
			
			if(combination.isEmpty())
			{
				for(ArrayList<String> p : allCombination)
				{
					if(!markedCombinations.contains(p))
					{
						policy = p;
						break;
					}
				}
			}
			else
			{					
				for(ArrayList<String> c : combination)
				{						
					if(!markedCombinations.contains(c))
					{
						policy = c;
						break;
					}
				}
				
				if(markedCombinations.containsAll(combination))
				{
					for(ArrayList<String> c : allCombination)
					{
						if(!markedCombinations.contains(c))
						{
							policy = c;
							break;
						}
					}
//					policy = getOriginalPolicy();
//					continue;
				}
			}
			
											
			System.out.println("Policy: " + policy);
			startVerifierTime = new Date();
			check = verifyDefence(policy, nodes);
			endVerifierTime = new Date();		
			System.out.println();				
			System.out.println("Time Taken for verifying the policy: " + (endVerifierTime.getTime() - startVerifierTime.getTime()) + " ms");				
			System.out.println();							
			
			if(check == true)
			{
				System.out.println("This is a valid policy");
				System.out.println("--------------------------------------------------------------------------------------------------");
				System.out.println();										
			}
			else
			{
				System.out.println("This is an invalid policy !!");
				System.out.println("--------------------------------------------------------------------------------------------------");
				System.out.println();
				
				/**
				 * Add all other subset combinations of invalid policy to marked combinations
				 */
				
				for(int i=1; i<policy.size(); i++)
				{
					combination.clear();
					generateCombination(policy, policy.size(), i);
					markedCombinations.addAll(new ArrayList<ArrayList<String>>(combination));
				}
			}
			
			/**
			 * Add the policy to marked policies
			 */
			
			markedCombinations.add(new ArrayList<String>(policy));
			
			/**
			 * Debug: For Checking the correctness of the logic
			 */
/*			System.out.println("Comb: " + combination);
			System.out.println("Marked Comb: " + markedCombinations);
			System.out.println("All Comb: " + allCombination);
			System.out.println("Marked Comb. Size: " + markedCombinations.size());
*/					
			
			++pass;
		}
		
		return pass;	
	}




	/**
	 *  The main function that prints all combinations of size r
	 * @param arr of size n. This function mainly uses combinationUtil()
	 * @param n is the size of the ArrayList arr
	 * @param r is the size of the combination (Min: 0, Max: Length of the ArrayList arr)
	 */
	public static void generateCombination(ArrayList<String> arr, int n, int r)
	{
		// A temporary array to store all combination one by one
		String data[] = new String[r];

		// Print all combination using temporary array 'data[]'
		combinationUtil(arr, data, 0, n-1, 0, r);		    
		return;

	}

	/**
	 * @param arr[]  ---> Input Array
	 * @param data[] ---> Temporary array to store current combination
	 * @param start & end ---> Staring and Ending indexes in arr
	 * @param index  ---> Current index in data[]
	 * @param r ---> Size of a combination to be printed		   		   		   		    
	 */
	public static ArrayList<String> combinationUtil(ArrayList<String> arr, String data[], int start, int end, int index, int r)
	{			
		//			clearExactSubSet();			
		ArrayList<String> tempSet = new ArrayList<String>();
		// Current combination is ready to be printed, print it
		if (index == r)
		{
			int count = 0;
			String[] temp = new String[r];
			//		    	System.out.println("\n");
			for (int j=0; j<r; j++)
			{
				//	            System.out.print(data[j] + " ");
				temp[j] = data[j] + " ";		            
			}
			//		        System.out.println();
			for(int j=0; j<r; j++)
			{
				temp[j] = temp[j].trim();
				String[] inputs = temp[j].split(" ");		        
				for(String s: inputs)
				{
					tempSet.add(s);		        	
					if(getExactSet().contains(s))
						count++;
				}		        		        		        		        		        
			}

			if(count > 0)
			{		        	
				combination.add(tempSet);
			}	
			return tempSet;
		}

		/*
		 * replace index with all possible elements. The condition
		 * "end-i+1 >= r-index" makes sure that including one element
		 * at index will make a combination with remaining elements
		 * at remaining positions		      
		 */
		for (int i=start; i<=end && end-i+1 >= r-index; i++)
		{
			data[index] = arr.get(i);
			combinationUtil(arr, data, i+1, end, index+1, r);
		}

		return null;
	}


	/**
	 * Main method to use the top-down analyzer of analysis for CVSS impact performance.
	 * @param betterCandidates is a HashSet<String> that is the set of nodes with CVSS impacts better than the input.
	 * @param exactCandidates is a HashSet<String> that has the set of all exact matches to the Preference-reasoner CVSS impact metric.	 
	 */

	public ArrayList<String> topDown(Set<String> betterCandidates, Set<String> exactCandidates)
	{
	
		/**
		 * Re-setting all variables
		 */
		
		reset();
		
		System.out.println("\nPerforming Top-Down Analysis:");
		System.out.println("===================================");
		
		HashSet<String> allCandidates = new LinkedHashSet<String>(exactCandidates);
		for(String s : betterCandidates)
			allCandidates.add(s);		


		ArrayList<String> policy = new ArrayList<String>();			

		for(String elements : allCandidates)
		{
			policy.add(elements);				
		}	

		if(!markedCombinations.contains(policy))		
			markedCombinations.add(new ArrayList<String>(policy));
		//			System.out.println("Marked Comb: " + markedCombinations);


		/*
		 * Things to perform on first pass to set up initial values and save them for later.
		 */			
		ArrayList<String> exacts = new ArrayList<String>();				

		for(String s : exactCandidates)
		{
			exacts.add(s);				
		}

		setExactSet(exacts);
		setOriginalPolicy(policy);								

		return policy;	
	}

	
	/**
	 * A method to help with the top-down analysis.
	 * @param policy is the defense policy to be verified.
	 * @param check is true if the policy is valid, else false.
	 * @param nodes is the ArrayList<Node> that contains information about the structure of the attack graph.
	 * @return pass which is of type int and records the total number of iterations
	 */
	
	public int topDownHelper(ArrayList<String> policy, boolean check, ArrayList<Node> nodes, int pass)
	{		
		Date	startVerifierTime, endVerifierTime;
//		int pass = 0;

		System.out.println("This is a valid policy");
		System.out.println("--------------------------------------------------------------------------------------------------");
		System.out.println();
		
		for(int i=policy.size(); i>0; i--)
		{
			generateCombination(policy, policy.size(), policy.size()-i);							
		}
		allCombination = new ArrayList<ArrayList<String>>(combination);
		allCombination.add(getOriginalPolicy());
//#UsedComb to test//						System.out.println("All Combinations: " + npg.allCombination);
		combination.clear();
		
		while(markedCombinations.size() < allCombination.size())
		{
			/**
			 * On all subsequent passes, generate combinations of the sub-set of the sub-set of the policy just verified.				
			 */
			
			combination.clear();
			
			if(pass == 0)
			{
				generateCombination(policy, policy.size(), 1);
				pass++;
			}
			else
			{
				generateCombination(policy, policy.size(), policy.size());
			}
			
			if(markedCombinations.containsAll(combination))
			{
				for(ArrayList<String> p : allCombination)
				{
					if(!markedCombinations.contains(p))
					{
						policy = p;
						break;
					}
				}
			}
			else
			{					
				for(ArrayList<String> c : combination)
				{						
					if(!markedCombinations.contains(c))
					{
						policy = c;
						break;
					}
				}
				
				if(markedCombinations.containsAll(combination))
				{
					policy = getOriginalPolicy();
					continue;
				}
			}
			
											
			System.out.println("Policy: " + policy);
			startVerifierTime = new Date();
			check = verifyDefence(policy, nodes);
			endVerifierTime = new Date();		
			System.out.println();				
			System.out.println("Time Taken for verifying the policy: " + (endVerifierTime.getTime() - startVerifierTime.getTime()) + " ms");				
			System.out.println();				
			
			if(check == true)
			{
				System.out.println("This is a valid policy");
				System.out.println("--------------------------------------------------------------------------------------------------");
				System.out.println();										
			}
			else
			{
				System.out.println("This is an invalid policy !!");
				System.out.println("--------------------------------------------------------------------------------------------------");
				System.out.println();
				
				/**
				 * Add all other subset combinations of invalid policy to marked combinations
				 */
				
				for(int i=1; i<policy.size(); i++)
				{
					combination.clear();
					generateCombination(policy, policy.size(), i);
					markedCombinations.addAll(new ArrayList<ArrayList<String>>(combination));
				}
			}
			
			/**
			 * Add the policy to marked policies
			 */
			
			markedCombinations.add(new ArrayList<String>(policy));
					
//			System.out.println("All Comb: " + npg.allCombination);
//			System.out.println("Marked Comb: " + npg.markedCombinations);
			
			++pass;			
		}
		
		return pass;
	
	}


}

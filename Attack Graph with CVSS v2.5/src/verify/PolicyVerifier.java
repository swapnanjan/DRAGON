package verify;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import tree.Node;


public class PolicyVerifier {

	/**
	 * getPrivilegedChild acts as a helper method to displayMonitorNodes method to display the nodes where monitors need to be placed
	 * @param n is the Node which is checked to see if any of its children are privilege nodes (type 1)
	 * @return the name of the privilege node which is a child of the passed Node n, else return null
	 */
	
	static String getPrivilegedChild(Node n)
	{		
		for(int i=0; i<n.getChildren().size(); i++)
		{		
			if(n.getChildren().get(i).getType() == 1)
			{
				return n.getChildren().get(i).getName();				
			}
		}
		
		return null;
	}
	
	
	/**
	 * displayMonitorNodes displays those privilege nodes (type 1) where placing a monitor can make a valid defence policy
	 * @param n is the array of all nodes, where monitors need to be placed 
	 */
	static void displayMonitorNodes(Node[] n)
	{
		for(int i=0; i<n.length; i++)
		{
//			String monitor = ;
			System.out.print((i+1) + ". " + getPrivilegedChild(n[i]) + " for protecting " + n[i].getName() + "\n");
		}
	}
	
	
	/**
	 * childrenHasPrivilegeNode method to return true if any child of a node is a Privilege node, for all other cases false.
	 * @param n the node to be analysed
	 * @return true if atleast one child is privilege type (type 1) else false
	 */
	
	static boolean childrenHasPrivilegeNode(Node n)
	{
		for(int i=0; i<n.getChildren().size(); i++)
		{
			if(n.getChildren().get(i).getType() == 1)
				return true;
		}
		return false;
	}
	
	
	/**
	 * stringArrayToNodeList method is a helper method to verifyDefence method. It returns a list of nodes whose names match the array of strings input by the user.
	 * @param array of String, and ArrayList of all nodes
	 * @return ArrayList of type Node, for all nodes whose names match those passed by the user in array
	 */
	
	static ArrayList<Node> stringArrayToNodeList(ArrayList<String> array, ArrayList<Node> nodes)
	{
		ArrayList<Node> list = new ArrayList<Node>();
		for(int i=0; i<nodes.size(); i++)
		{
			for(int j=0; j<array.size(); j++)
			{
				if(nodes.get(i).getName().equals(array.get(j)))
				{
					list.add(nodes.get(i));
				}
					
			}
		}
		
		return list;
	}
	
	
	/**
	 * setOfAllExploits method returns the set of all exploits (type 2) in the tree/graph 
	 * @param ArrayList of all nodes
	 * @return Set of all exploits (type 2)
	 */
	static HashSet<Node> setOfAllExploits(ArrayList<Node> nodes)
	{
		HashSet<Node> exploits = new LinkedHashSet<Node>();
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 2)
			{				
				exploits.add(nodes.get(i));
			}
					
		}
		
		return exploits;
	}
	
	
	/**
	 * verifyDefence is the method which checks if the policy proposed by the System Admin is indeed a valid Defense Policy
	 * @param policy is an ArrayList of type String which takes in the names of the nodes which need to be negated as proposed by the System Admin
	 * @param nodes is an ArrayList of type Node, which contains the list of all nodes in the Tree/Graph
	 * @return true if the passed policy is indeed a valid policy, else return false
	 */
	
	public static boolean verifyDefence(ArrayList<String> policy, ArrayList<Node> nodes)
	{		
		
		HashSet<Node> allExploits = setOfAllExploits(nodes); //Setting up a set of All Exploits that exist in the tree
		
		/*
		 * Checking to see that all nodes are added
		 */
/*		System.out.println("\nExploits: ");
		for(Node n : allExploits)
		{
			System.out.print(n.getName() + " ");
		}
*/		
		ArrayList<Node> sentPolicy = stringArrayToNodeList(policy, nodes); // Converting the sent ArrayList of String to a list of type Node
		
		/*
		 * Checking to see that all nodes are added
		 */
/*		System.out.println("\nSentPolicy: ");
		for(Node n : sentPolicy)
		{
			System.out.print(n.getName() + " ");
		}
*/		
		
		
		Node[] exploits = allExploits.toArray(new Node[0]);		
		ArrayList<Node> markedPrivileges = new ArrayList<Node>();
		
		for(int i=0; i<exploits.length; i++)
		{
			for(int j=0; j<sentPolicy.size(); j++)
			{
				if(exploits[i].getChildren().contains(sentPolicy.get(j)))
						{
//							System.out.println("\nRemoving exploit: " + exploits[i].getName());
							allExploits.remove(exploits[i]);
						}
				if(sentPolicy.get(j).getType() == 1)
				{
//					System.out.println("\nMarked privilege: " + sentPolicy.get(j).getName());
					markedPrivileges.add(sentPolicy.get(j));
				}
			}
		}
		
		Node[] exploitsLeft = allExploits.toArray(new Node[0]);		
		
				
		
		for(int i=0; i<exploitsLeft.length; i++)
		{
			for(int j=0; j<markedPrivileges.size(); j++)
			{				
				
				if(exploitsLeft[i].getParents().contains(markedPrivileges.get(j)))
				{
					allExploits.remove(exploitsLeft[i]);
				}
			}
		}
		
		if(allExploits.isEmpty())
			return true;
		else
		{
			Node[] stillExploitsLeft = allExploits.toArray(new Node[0]);
			int count = 0;
			for(int i=0; i<stillExploitsLeft.length; i++)
			{
				if(childrenHasPrivilegeNode(stillExploitsLeft[i]) == true)
				{
					count++;					
				}
					
			}
			if(count == stillExploitsLeft.length)
			{
				System.out.println("\nPlace Monitors on: ");
				displayMonitorNodes(stillExploitsLeft);
				return true;
			}
						
		}
		
		
		return false;
	}
	
	
	/**
	 * verify is a method which checks if the assignment returned by the Preference Reasoner is indeed a valid policy from attacker perspective.
	 * It looks at each Exploit (Type 2) as a conjunction of Leaves (Type 0) and Privileges (Type 1)
	 * @param root of type Node is the root node of the Tree/Graph
	 * @param assignment is a Set of type String which contains the set of assignment to verify, if root node can be compromised
	 * @param nodes is an ArrayList of type Node which contains the list of all nodes in the Tree/Graph
	 * @throws InterruptedException
	 * @return true if the assignment can satisfy the root, else returns false
	 */
	
	public boolean verify(Node root, Set<String> assignment, ArrayList<Node> nodes) throws InterruptedException
	{
		int len = assignment.size();
		if(assignment.contains(root.getName()))			
			return true;			
		else
		{			
		String[] checkSat = new String[assignment.size()];
//		System.out.println("\nSize= "+assignment.size());
		assignment.toArray(checkSat);		
		for(int p=0; p<checkSat.length; p++)			
		{			
			int pos = 0;
//			System.out.println("\n checkSat= "+checkSat[p]);
			for(int y=0; y<nodes.size(); y++)
			{
				if(checkSat[p].equals(nodes.get(y).getName()))
					{
					pos = y;
//					System.out.println("Father of Node["+pos+"]= "+nodes[pos].getParents().get(0).getName());
					break;
					}
			}
			
			for(int y=0; y<nodes.get(pos).getParents().size(); y++)
			{				
				if(nodes.get(pos).getParents().get(y).getType() == 1)
				{
					assignment.add(nodes.get(pos).getParents().get(y).getName());					
				}
				else if(nodes.get(pos).getParents().get(y).getType() == 2)
				{
					int ccnt = 0;
					for(int j=0; j<nodes.get(pos).getParents().get(y).getChildren().size(); j++)
					{
						if(assignment.contains(nodes.get(pos).getParents().get(y).getChildren().get(j).getName()))
						{
//							System.out.println("\nChildren of "+ nodes[pos].getParents().get(y).getName() +" = "+ nodes[pos].getParents().get(y).getChildren().get(j).getName());
							ccnt++;
						}
					}
					if(ccnt == nodes.get(pos).getParents().get(y).getChildren().size())
						assignment.add(nodes.get(pos).getParents().get(y).getName());					
				}
				else if(nodes.get(pos).getParents().get(y).getType() == 0)
				{
					return false;
				}
				
			}
			
		}
		int newLen = assignment.size();
//		System.out.println(" Assignment= "+assignment);		//For Checking
		if(len == newLen)
			return false;
		else
		{
			return verify(root, assignment, nodes);		
			
		}
		}
		
	}

}

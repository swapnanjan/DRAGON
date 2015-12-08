package verify;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import tree.Node;

public class TreeValidator {

	/**
	 * A method to validate the input attack graph .gml file of any redundant node names
	 * @param nodes is the list of nodes in the tree in the input .gml file
	 * @return true/false. The method returns true if the .gml file is valid else false
	 */
	public boolean checkGMLValidity(ArrayList<Node> nodes)	
	{		

		Set<String> uniqueNodes = new LinkedHashSet<String>();
		List<String> redundantNodes = new ArrayList<String>();

		for(Node n : nodes)
		{
			if(!uniqueNodes.add(n.getName()))
			{
				redundantNodes.add(n.getName());
			}
		}

		if(redundantNodes.size() > 0)
		{
			System.out.println();
			System.out.println("===============================================================================");
			System.out.println();
			System.out.println("The file seems to contain redundant nodes");
			System.out.println("===============================================================================");
			System.out.println();
			System.out.println("The redundant nodes are: ");
			System.out.println("--------------------------------");
			int count = 0;
			for(String name : redundantNodes)
			{
				System.out.println(++count + ") " + name);
			}
			System.out.println();			
			return false;
		}
		else
			return true;
	}

	
	/**
	 * A method to validate the input attack graph file of any redundant node names
	 * @param pnodes is the list of Privilege nodes in the tree
	 * @param enodes is the list of Exploit nodes in the tree
	 * @param lnodes is the list of Leaf nodes (Configuration nodes) in the tree
	 * @return true/false. The method returns true if the attack graph file is valid else false
	 */
	
	public boolean checkAttackGraphValidity(List<String> pnodes, List<String> enodes, List<String> lnodes)
	{
		/**
		 * For spotting the redundancies
		 */
		Set<String> allNodes = new LinkedHashSet<String>();		
		
		/**
		 * For storing the redundant node names
		 */
		List<String> redundantNodes = new ArrayList<String>();
		
		
		for(String p : pnodes)
		{
			if(!allNodes.add(p))
			{
				redundantNodes.add(p);
			}
		}
		
		for(String e : enodes)
		{
			if(!allNodes.add(e))
			{
				redundantNodes.add(e);
			}
		}
		
		for(String l : lnodes)
		{
			if(!allNodes.add(l))
			{
				redundantNodes.add(l);
			}
		}
		if(redundantNodes.size() > 0)
		{
			System.out.println();
			System.out.println("===============================================================================");
			System.out.println();
			System.out.println("The file seems to contain redundant nodes");
			System.out.println("===============================================================================");
			System.out.println();
			System.out.println("The redundant nodes are: ");
			System.out.println("--------------------------------");
			int count = 0;
			for(String name : redundantNodes)
			{
				System.out.println(++count + ") " + name);
			}		
			System.out.println();			
			return false;
		}
		else		
			return true;
	}
	
	public boolean checkLeafValidity(ArrayList<Node> nodes)
	{
		List<String> invalidNodes = new ArrayList<String>();
		
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 0)
			{
				for(int j=0; j<nodes.get(i).getParents().size(); j++)
				{
					if(nodes.get(i).getParents().get(j).getType() == 0)
						invalidNodes.add(nodes.get(i).getParents().get(j).getName());
				}
			}
		}
		
		if(invalidNodes.size() > 0)
		{
			System.out.println();
			System.out.println("===============================================================================");
			System.out.println();
			System.out.println("The file seems to contain leaf nodes with children");
			System.out.println("===============================================================================");
			System.out.println();
			System.out.println("The invalid leaf nodes are: ");
			System.out.println("--------------------------------");
			int count = 0;
			for(String name : invalidNodes)
			{
				System.out.println(++count + ") " + name);
			}					
			System.out.println();
			return false;
		}
		else
			return true;
	}
	
}

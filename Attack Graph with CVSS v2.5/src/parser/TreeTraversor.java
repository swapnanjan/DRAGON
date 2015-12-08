package parser;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Stack;

import tree.*;


public class TreeTraversor {

	public static Node            n;		
	public static Iterator<Node>  nIter1;
	
	/**
	 * A method to print out the nodes of the attack graph in Depth-First order.
	 * @param nodes is the ArrayList<Node> that contains information about the entire attack graph.
	 */
	public void dfs(ArrayList<Node> nodes)
	{
		/*
		 * 			// Print the Nodes in Depth First Traversal order 
		 */
		n = nodes.get(0);
		ArrayList<String> output = new ArrayList<String>();		// This will contain the traversal order
		Stack<Node> st = new Stack<Node>();		// Stack implemented for DFS
		st.push(n);												// Push the root node on TOS
		while (!st.isEmpty())									// Iterate until TOS is empty
		{
			nIter1 = st.peek().getChildren().iterator();		// Get the children of the node on TOS			
			output.add(st.pop().getName());			// Add the node to the Output array list which is marked and all it's children are assigned to gtnIter1
			while(nIter1.hasNext())							// While all it's child nodes haven't been traversed
			{
				st.push(nIter1.next());						// Push the Children of the child node to the TOS
			}
		}
		System.out.println(output);								// Print out the traversal
		output.clear();
		System.out.println();
	}
	
	
	
	/**
	 * A method to print out the nodes of the attack graph in Infix order.
	 * @param nodes is the ArrayList<Node> that contains information about the entire attack graph.
	 */	
	public void infix(ArrayList<Node> nodes)
	{
		/*
		 * 			// Print the Nodes Infix Traversal 
		 */
		
		n = nodes.get(0);
		ArrayList<String> output_infix = new ArrayList<String>();		// This will contain the traversal order
		String temp[] = new String [1000] ;
		Stack<Node> st1 = new Stack<Node>();		// Stack implemented for DFS
		Stack<String> st_flip = new Stack<String>();
		st1.push(n);												// Push the root node on TOS
		int l=0;
		while (!st1.isEmpty())									// Iterate until TOS is empty
		{
			nIter1 = st1.peek().getChildren().iterator();		// Get the children of the node on TOS 
			temp[l] = st1.pop().getName();			// Add the node to the Output array list which is marked and all it's children are assigned to gtnIter1			
			while(nIter1.hasNext())							// While all it's child nodes haven't been traversed
			{
				st1.push(nIter1.next());						// Push the Children of the child node to the TOS
			}
			l++;
		}
		temp[l] = "Empty";
		int o=0;
		while (!temp[o].equalsIgnoreCase("Empty"))
		{
			st_flip.push(temp[o]);								// Do a DFS from each leaf node to the root node
			o++;
		}
		while(!st_flip.isEmpty())
		{
			output_infix.add(st_flip.pop());			
		}
		System.out.println(output_infix);						// Print the Infix traversal order

	}

}

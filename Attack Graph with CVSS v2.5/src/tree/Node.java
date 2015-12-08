package tree;

import impact_analysis.PolicyGenerator;

import java.util.*;


/**
 * Represents a node in the attack graph, including its name, the type of node it is (privilege, exploit or leaf node), 
 * the list of parents, and children of that node in the graph.
 * @author Swapnanjan Chatterjee, schatt@iastate.edu
 */
public class Node extends PolicyGenerator {
	
	
	/**
	 * The name of the goal. This also serves as an informal description of
	 * the goal.
	 */
	private String name;
	
	/**
	 * The type (AND/OR) of the goal.
	 */
	private int type;
	
	
	
	/**
	 * The list of fathers(Parents) for every goal node of type Node.
	 */
	private ArrayList<Node> parents;
	

	/**
	 * The list of children for every goal node.
	 */
	private ArrayList<Node> children;
	
	
	
	/**
	 * Constructs a Node object with an empty name, type = 0(leaf), and 
	 * initializes the C,I,A parameters to 7, 7, 7 (Higher than accepted values).	 
	 */	
	public Node() {
		//super();
		this.name = "";
		this.type = 0;
		this.children = new ArrayList<Node>();
		this.parents = new ArrayList<Node>();
		this.C = 7;
		this.I = 7;
		this.A = 7;
	}
	
	/**
	 * Constructs a Node object with an empty name, type = 0(leaf), and 
	 * initializes the C,I,A parameters to 7, 7, 7 (Higher than accepted values).
	 * @param name the name of the Node.	
	 * @param type the type of Node node i.e: 0=leaf, 1=OR, 2=AND.
	 */
	public Node(String name2, int type2) {
		this.name = name2;
		this.type = type2;
		this.parents = new ArrayList<Node>();
		this.children = new ArrayList<Node>();
		this.C = 7;
		this.I = 7;
		this.A = 7;
	}

	/**
	 * Gets the name of the Node.
	 * @return the name of the Node.
	 */
	public String getName() {
		return name;
	}
	/**
	 * Sets a new name for the Node.
	 * @param name the name to be set for the Node.
	 */
	public void setName(String name2) {
		name = name2;
	}
	/**
	 * Gets the type of the Node.
	 * @return the type
	 */
	public int getType() {
		return type;
	}
	/**
	 * Sets the type for the Node.
	 * @param type is type 0, 1 or 2 (0 = Leaf, 1 = OR, and 2 = AND)
	 */
	public void setType(int type2) {
		type = type2;
	}
	
	
	
	/**
	 * Gets the list of list of parents(fathers) for each node.
	 * @return the fathers
	 */
	public ArrayList<Node> getParents() {
		return parents;
	}
	
	
	
	/**
	 * Gets the list of list of children for each node.
	 * @return children for the present node which is of type ArrayList<Node>.
	 */
	public ArrayList<Node> getChildren() {
		return children;
	}
	
	
	
	
	/**
	 * Sets a new a list of parents at one-shot for a node.
	 * @param parents2 is an ArrayList<Node> which is the list of parents to be set for the given Node
	 */
	public void setParents(ArrayList<Node> parents2) {
		parents = parents2;
	}

	
	/**
	 * Adds 1 parent to any node at a time
	 * @param parent2 is variable of type Node, to be set as a parent for the given Node
	 */

	public void addParent(Node parent2){
		parents.add(parent2);
	}

	
	
	/**
	 * Sets a new a list of fathers at one-shot for a node.
	 * @param children2 is an ArrayList<Node> to be set as the list of children for the given Node
	 */
	public void setChildren(ArrayList<Node> children2) {
		children = children2;
	}
	
	
	/**
	 * Adds 1 child to any node at a time
	 * @param children2 is a variable of Node to be set as one of the children for the given Node
	 */

	public void addChild(Node children2){
		this.children.add(children2);
	}
		
	

	/*
	 *  ##### The next part of the class helps deal with C,I,A analysis #####
	 */

	
	
	/**
	 * The C, I, A impacts on each Node 
	 * Here, each impact component C, I, and A have 3 levels (Very Hi = 6, Hi = 5, Hi Med = 4, Lo Med = 3, Lo = 2, Very Lo = 1), but they can have any number of levels encoded
	 */
	
	private int C, I, A;
	
	/**
	 * A method to encode the impact parameters (C, I, and A).
	 */
	
	public void setImpacts(int C, int I, int A)
	{
		this.C = C;
		this.I = I;
		this.A = A;
	}
	
	/**
	 * A method to get the impact value for Confidentiality (C) type impact.
	 * @return C is a numeric value that is the valuation of the Confidentiality Impact.
	 */
	
	public int getImpactC()
	{
		return C;
	}
		
	/**
	 * A method to get the impact value for Integrity (I) type impact.
	 * @return I is a numeric value that is the valuation of the Integrity Impact.
	 */
	
	public int getImpactI()
	{
		return I;
	}

	/**
	 * A method to get the impact value for Availability (A) type impact
	 * @return A is a numeric value that is the valuation of the Availability Impact. 
	 */
	
	public int getImpactA()
	{
		return A;
	}

	
	
}

package parser;

import impact_analysis.*;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

import tree.Node;


public class TreeParser extends ImpactAnalyzer{
	
	/**
	 * For storing all the Privilege nodes
	 */
	private static ArrayList<String> pnodes = new ArrayList<String>();
	
	/**
	 * A method to get all the privilege nodes in the tree
	 * @return pnodes is an ArrayList<String> returns the list of all privilege nodes in the tree
	 */
	public ArrayList<String> getPnodes()
	{
		return pnodes;
	}
		
	
	/**
	 * For storing all the Exploit nodes
	 */
	private static ArrayList<String> enodes = new ArrayList<String>();
	
	/**
	 * A method to get all the exploit nodes in the tree
	 * @return enodes is an ArrayList<String> returns the list of all exploit nodes in the tree
	 */
	public ArrayList<String> getEnodes()
	{
		return enodes;
	}
	
	/**
	 * For storing all the leaf nodes
	 */
	private static ArrayList<String> lnodes = new ArrayList<String>();
	
	/**
	 * A method to get all the leaf nodes in the tree
	 * @return lnodes is an ArrayList<String> returns the list of all leaf nodes in the tree
	 */
	public ArrayList<String> getLnodes()
	{
		return lnodes;
	}
	

	/**
	 * A method to parse the input attack graph file.
	 * @param file contains the file-path + file-name of the input file.
	 * @param nodes is the ArrayList<Node> that contains information about the entire attack graph.
	 */
	@SuppressWarnings({ "resource", "unused" })
	public void parse(String file, ArrayList<Node> nodes)
	{
		
		
		int node_count = 0;  // For counting the total no. of nodes in the Graph

		int count = 0, count1 = 0;	// count -> For counting the no. of goals in the graph, count1 -> For counting the no. of leaves in the graph 
		int lineNumber = 0;		
						
		
	try{					
		/*
		 *  Open the file that is mentioned in the file (Along with the path)
		 */
		FileInputStream fstream = new FileInputStream(file);
		// Get the object of DataInputStream
		DataInputStream in = new DataInputStream(fstream);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));			  
		String strLine;		
		String input = new String();	
		int temp_node_count = 0, temp_flag = 0;
		int node_type = 0;

		// ** Read File Line By Line **
		while ((strLine = br.readLine()) != null)   {
			lineNumber ++;
			// Print the content on the console				  
//			System.out.println ("Line " + lineNumber + ": " + strLine);
			strLine = strLine.replace(" ", "");
			if(strLine.contains("#"))
			{
				strLine = strLine.replace("#", "");
//				System.out.println(lineNumber + ": Comment: " + strLine);
			}
			else if (strLine.equalsIgnoreCase("END"))
			{
				break;
			}
			else if(strLine.contains("pnodes"))
			{
				String temp1[] = strLine.split(":");
				String pNodes[] = temp1[1].split(",");								
				pNodes[pNodes.length-1] = pNodes[pNodes.length-1].replace(";", "");					
//				System.out.print("pNodes: ");
				for(int i=0; i<pNodes.length; i++)
				{
//					System.out.print(pNodes[i]);
					pnodes.add(pNodes[i]);
					count++;						
				}
//				System.out.println("\ncount= "+count);

			}
			else if(strLine.contains("enodes"))
			{
				String temp1[] = strLine.split(":");
				String eNodes[] = temp1[1].split(",");								
				eNodes[eNodes.length-1] = eNodes[eNodes.length-1].replace(";", "");										
//				System.out.print("eNodes: ");
				for(int i=0; i<eNodes.length; i++)
				{
//					System.out.print(eNodes[i]);
					enodes.add(eNodes[i]);
					count++;				
				}
//				System.out.println("\ncount= "+count);
			}
			else if(strLine.contains("lnodes"))
			{
				String temp1[] = strLine.split(":");
				String lNodes[] = temp1[1].split(",");								
				lNodes[lNodes.length-1] = lNodes[lNodes.length-1].replace(";", "");										
//				System.out.print("lNodes: ");
				for(int i=0; i<lNodes.length; i++)
				{
//					System.out.print(lNodes[i]);
					lnodes.add(lNodes[i]);
					count1++;				
				}
//				System.out.println("\ncount1= "+count1);
			}
			else if(strLine.contains("root"))
			{
				if(strLine.contains(","))
				{
					throw new IOException("Invalid Syntax");					
				}
				String temp1[] = strLine.split(":");								
				String root[] = temp1[1].split(";");					
//				System.out.print("Root: "+root[0]);

				for(int j=0; j<pnodes.size(); j++)
				{					
					if (input.equalsIgnoreCase(pnodes.get(j)))
					{
//						System.out.print("\n Pnodes = "+pnodes);
						node_type = 1;
						break;
					}							 
				}						 
				for (int j=0; j<enodes.size(); j++)
				{							  							  
					if(input.equalsIgnoreCase(enodes.get(j)))
					{							
//						System.out.print("\n Enodes = "+enodes);
						node_type = 2;
						break;
					}
				}
				nodes.add(new Node(root[0], 1));  								
//				System.out.println("\nSize of N= "+nodes.size());
//				System.out.print("\nN[0].name: " + nodes.get(node_count).getName());
				node_count++; 				  							 						  					 
//				System.out.println("Setting up: pnodes= "+pnodes+" & enodes= "+enodes);				
			}
			else if(strLine.equalsIgnoreCase("goals:"))
			{
				strLine = br.readLine();
				while(!strLine.equalsIgnoreCase("sloag"))
				{
					lineNumber++;
					strLine.replaceAll(" ", "");
//					System.out.println("\nLine " + lineNumber + ": " +strLine);
					String temp1[] = strLine.split("-->");
					String father = temp1[0].trim();
					String children[] = temp1[1].split(",");								
					children[children.length-1] = children[children.length-1].replace(";", "");
					
					
					// ### For finding the node number of the father ###### 							
					int node_father = 0;
					for(int j=0; j< nodes.size(); j++){					  					  
						  if(father.equalsIgnoreCase(nodes.get(j).getName())){
							  node_father = j;
							  break;
						  }
					}
					
//					System.out.println("Node_Father= "+node_father);
					
					
					for(int i=0; i<children.length; i++)
					{
						children[i] = children[i].trim();
//						System.out.print("Children"+i+" = "+children[i]+ " ");							
					}					
					
					for(int k = 0; k < children.length; k++)
					{
						
																									
//##### For finding the node type of the node #######							
					node_type = 0;
					for(int j=0; j<pnodes.size(); j++){

						if (children[k].equalsIgnoreCase(pnodes.get(j))){
//							System.out.print("\n Pnodes = "+pnodes);
							node_type = 1;
							break;
						}							 
					}						 
					for (int j=0; j<enodes.size(); j++){							  							  
						if(children[k].equalsIgnoreCase(enodes.get(j))){								
//							System.out.print("\n Enodes = "+enodes);
							node_type = 2;
							break;
						}							  							  
					}

						if(node_type == 0)
					{
							throw new IOException("The node is not found in the list of OR/AND nodes");						
					}

					
					node_count = nodes.size();						

//					System.out.print("\n node_count = "+node_count);						
						for(int p = 0; p <= node_count; p++)
						{
							if (node_count == 0 || p == node_count)
							{									
							nodes.add(node_count, new Node(children[k], node_type));
							break;
							}
							
							if(node_count > 0 && children[k].equals(nodes.get(p).getName()))
							{
								temp_flag = 1;
								temp_node_count = node_count;
								node_count = p;
								break;
							}
							

						}
						
						
						
//###### For assigning the father and children of each node ######							
						
						//The Father is assigned the child node
						nodes.get(node_father).addChild(nodes.get(node_count)); 								
						for(int m=0; m<node_count; m++)
						{
							if(father.equalsIgnoreCase(nodes.get(m).getName()))
									nodes.get(node_count).addParent(nodes.get(m));
						}
						
												
						
					}
					
//					System.out.println();
					strLine = br.readLine();
					
				}
				lineNumber++;
			}
			else if(strLine.equalsIgnoreCase("leaves:"))
			{

				strLine = br.readLine();
				while(!strLine.equalsIgnoreCase("sevael"))
				{
					lineNumber++;
					strLine.replaceAll(" ", "");
//					System.out.println("\nLine " + lineNumber + ": " +strLine);
					String temp1[] = strLine.split("-->");
					String father = temp1[0];
					String children[] = temp1[1].split("\\,+");								
					children[children.length-1] = children[children.length-1].replace(";", "");
					
					
					
					// ### For finding the node number of the father ###### 							
					int node_father = 0;
					for(int j=0; j< node_count; j++){					  					  
						  if(father.equalsIgnoreCase(nodes.get(j).getName())){
							  node_father = j;
							  break;
						  }
					}
					
					for(int i=0; i<children.length; i++)
					{
						children[i] = children[i].trim();
//						System.out.print("Children"+i+" = "+children[i]+ " ");
					}					
					
					for(int k = 0; k < children.length; k++)
					{
					node_type = 0;
					for(int j=0; j<lnodes.size(); j++){

						if (children[k].equalsIgnoreCase(lnodes.get(j))){
//							System.out.print("\n Lnodes = "+lnodes);
							node_type = 0;
							break;
						}							 
					}						 					
					
					node_count = nodes.size();						

//					System.out.print("\n node_count = "+node_count);						
						for(int p = 0; p <= node_count; p++){
							
							if (node_count == 0 || p == node_count){								
								 nodes.add(node_count, new Node(children[k], 0));  																 
								 break;
							  }
							
							if(node_count > 0 && children[k].equals(nodes.get(p).getName()))
							{
								temp_flag = 1;
								temp_node_count = node_count;
								node_count = p;
//								System.out.println("\n temp_flag = " + temp_flag+" node_count = "+node_count);
								break;
							}								
						}
						
						
						
//###### For assigning the father and children of each node ######							
						
						//The Father is assigned the child node
						nodes.get(node_father).addChild(nodes.get(node_count)); 							
						for(int m=0; m<node_count; m++)
						{
							if(father.equalsIgnoreCase(nodes.get(m).getName()))
									nodes.get(node_count).addParent(nodes.get(m));
						}
																								
						
					}
					
					strLine = br.readLine();
					
				}
				lineNumber++;
			
			}
			else
			{
				throw new IOException("Syntax Error. Invalid keyword.");				
			}
		}
		// ** Close the input stream **
		in.close();
	}catch (Exception e){//Catch exception if any
		System.err.println("\nThere was an error parsing the input File: " + file + " at Line: " + lineNumber);
		System.out.println("Error: " + e.getMessage());
	}
	}

}

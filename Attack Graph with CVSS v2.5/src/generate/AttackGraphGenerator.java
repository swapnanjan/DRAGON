package generate;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;

import tree.Node;

public class AttackGraphGenerator {

	/**
	 * A method to generate an Acyclic Attack Graph.
	 * @param node_count is the maximum number of nodes allowed in the tree
	 * @param degree is the maximum out-degree of any node 
	 * @return nodes which is an ArrayList<Node> containing info about the attack tree just set-up 
	 */
	public ArrayList<Node> generateAttackGraph(int node_count, int degree) {		

		ArrayList<Node> nodes = new ArrayList<Node>();
		Random rand = new Random(123456789l);
	
		int p_count = 0;
		int e_count = 0;
		int l_count = 0;
		HashSet<Integer> marked_indices = new LinkedHashSet<Integer>();
		int level = 1;
		int index = 0;
		nodes.add(new Node("p1", 1));		
		p_count++;
		double prev_count = 0;
		/**
		 * This is the place where the entire tree is set-up.
		 */
		while((e_count + p_count + l_count) < (node_count- (degree*degree)/2))
		{					
			int random_degree = 1 + rand.nextInt(degree);			
			for(int i=0; i<random_degree; i++)
			{					
				if(nodes.get(index).getType() == 1)
				{					
					nodes.add(new Node("e"+(e_count+1), 2));
					e_count++;
					int gen_index = nodes.size()-1;
					nodes.get(index).addChild(nodes.get(gen_index));
					nodes.get(gen_index).addParent(nodes.get(index));
					marked_indices.add(gen_index);
				}
				if(nodes.get(index).getType() == 2)
				{	
					int random_picker = rand.nextInt(10);
					if(random_picker >= 5 && (e_count + p_count + l_count) < (node_count - (degree*(degree)/2)))
					{
						nodes.add(new Node("p"+(p_count+1), 1));
						p_count++;
						int gen_index = nodes.size()-1;
						nodes.get(index).addChild(nodes.get(gen_index));
						nodes.get(gen_index).addParent(nodes.get(index));					
						marked_indices.add(gen_index);					
					}
					else
					{
						nodes.add(new Node("c"+(l_count+1), 0));
						l_count++;
						int gen_index = nodes.size()-1;
						nodes.get(index).addChild(nodes.get(gen_index));
						nodes.get(gen_index).addParent(nodes.get(index));					
						marked_indices.add(gen_index);
					}
				}				
			}	
			/**
			 * Preventing from encountering exception.
			 * This condition is when all nodes generated in final level are leaf nodes.
			 */
			int count = 0;
			for(int k=index; k<nodes.size(); k++)
			{
				if(nodes.get(k).getType() == 0)
					count++;
			}
			if(count == nodes.size()-index)
				break;
			else
				index++;			
			//			Object[] siblings = marked_indices.toArray();											

		}

		/**
		 * Locating indices of all privilege nodes without a child presently.
		 */
		ArrayList<Integer> pNodes_wo_child = new ArrayList<Integer>();
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 1 && nodes.get(i).getChildren().size() == 0)
				pNodes_wo_child.add(i);
		}
		
		/**
		 * Generating child for each of the privilege nodes who have no children presently.
		 */
		for(int i=0; i<pNodes_wo_child.size(); i++)
		{
			nodes.add(new Node("e" + (++e_count), 2));
			nodes.get(pNodes_wo_child.get(i)).addChild(nodes.get(nodes.size()-1));
			nodes.get(nodes.size()-1).addParent(nodes.get(pNodes_wo_child.get(i)));
		}
		
		/**
		 * Assigning all exploit nodes left without a child an existing leaf node as child.
		 */
		
		for(int i=0; i<nodes.size(); i++)
		{
			if(nodes.get(i).getType() == 2 && nodes.get(i).getChildren().size() == 0)
			{
				int random_index = rand.nextInt(nodes.size());
				while(nodes.get(random_index).getType() != 0)
				{
					random_index = rand.nextInt(nodes.size());
				}
				nodes.get(i).addChild(nodes.get(random_index));
				nodes.get(random_index).addParent(nodes.get(i));
			}
		}

/*
		for(Node node : nodes)
		{
			System.out.println("\n\n" + node.getName());
			System.out.println("Parents:");
			for(Node parent : node.getParents())
			{
				System.out.print(parent.getName() + " ");
			}
			System.out.println("\nChildren:");
			for(Node child : node.getChildren())
			{
				System.out.print(child.getName() + " ");
			}
		}
*/
		return nodes;
	}

}

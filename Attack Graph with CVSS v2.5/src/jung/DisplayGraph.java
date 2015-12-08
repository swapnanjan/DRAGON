package jung;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.util.ArrayList;

import javax.swing.JFrame;

import org.apache.commons.collections15.Transformer;

import tree.*;

import driver.AttackGraphMain;

//import edu.uci.ics.jung.algorithms.layout.CircleLayout;
import edu.uci.ics.jung.algorithms.layout.DAGLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.DirectedSparseGraph;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.DefaultModalGraphMouse;
import edu.uci.ics.jung.visualization.control.ModalGraphMouse;

public class DisplayGraph {
	
	/**
	 * A method to display the attack graph visually to the user using Jung API.
	 * @param nodes is the ArrayList<Node> that contains information about the structure of the attack graph. 
	 */
	public void displayGraph(ArrayList<Node> nodes) {

		DirectedSparseGraph<String, String> g = new DirectedSparseGraph<String, String>();	  

		int edgeCount = 0;

		for(int i=0; i<nodes.size(); i++)
		{    	
			if(!g.containsVertex(nodes.get(i).getName()))
				g.addVertex(nodes.get(i).getName());
			for(int j=0; j<nodes.get(i).getChildren().size(); j++)
			{
				if(!g.containsVertex(nodes.get(i).getChildren().get(j).getName()))
					g.addVertex(nodes.get(i).getChildren().get(j).getName());

				g.addEdge(String.valueOf(++edgeCount), nodes.get(i).getName(), nodes.get(i).getChildren().get(j).getName());

			}

		}


		/*
    int edgeCount = 0;
    for(int i=0; i<nodes.size(); i++)
    {
    	for(int j=0; j<nodes.get(i).getChildren().size(); j++)
    	{    		
    		g.addEdge(String.valueOf(++edgeCount), nodes.get(i).getName(), nodes.get(i).getChildren().get(j).getName());    		
    	}
    }
		 */    


		/**
		 * For Cyclic Layout
		 */
		//    VisualizationViewer<String, String> vv =  new VisualizationViewer<String, String>(new CircleLayout<String, String>(g), new Dimension(800, 700));

		/**
		 * For DAG Layout
		 */
		VisualizationViewer<String, String> vv =  new VisualizationViewer<String, String>(new DAGLayout<String, String>(g), new Dimension(1300, 600));        
		

		//This code displays the name of the nodes
		vv.getRenderContext().setVertexLabelTransformer(new Transformer<String, String>() {
			@Override
			public String transform(String arg0) {
				return arg0;
			}
		});


		//This code displays the name of the edge
		/*
    vv.getRenderContext().setEdgeLabelTransformer(new Transformer<String, String>() {
        @Override
        public String transform(String arg0) {
          return arg0;
        }
      });
		 */    

		vv.getRenderer().setVertexRenderer(new MyRenderer());


		final DefaultModalGraphMouse<String, Number> graphMouse = new DefaultModalGraphMouse<String, Number>();
		graphMouse.setMode(ModalGraphMouse.Mode.PICKING);
		vv.setGraphMouse(graphMouse);

		JFrame frame = new JFrame();
		frame.getContentPane().add(vv);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.pack();
		frame.setVisible(true);
	}


	static class MyRenderer implements Renderer.Vertex<String, String> {
		@SuppressWarnings("static-access")
		@Override
		public void paintVertex(RenderContext<String, String> rc, Layout<String, String> layout, String vertex) {

			AttackGraphMain m = new AttackGraphMain();
			ArrayList<Node> nodeList = m.nodes;
			int index = 0;
			for(int i=0; i<nodeList.size(); i++)
			{
				if(nodeList.get(i).getName().equals(vertex))
				{
					index = i;
					break;
				}
			}

			GraphicsDecorator graphicsContext = rc.getGraphicsContext();
			Point2D center = layout.transform(vertex);						
			Shape shape = null;
			Color color = null;	      
			if(nodeList.get(index).getType() == 0) {
				shape = new Rectangle((int) center.getX() - 10, (int) center.getY() - 10, 20, 20);
				color = new Color(255, 0, 0);
			} else if(nodeList.get(index).getType() == 2) {
				shape = new Rectangle((int) center.getX() - 10, (int) center.getY() - 20, 20, 40);
				color = new Color(0, 0, 255);
			} else if(nodeList.get(index).getType() == 1) {								
					shape = new Ellipse2D.Double((int) center.getX() - 10, (int) center.getY() - 10, 20, 20);
					color = new Color(0, 255, 0);				
			}
			graphicsContext.setPaint(color);
			graphicsContext.fill(shape);
		}

	}
}
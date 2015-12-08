package parser;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

import tree.*;

public class CVSSParser {

	private int lineNumber = 0;
	
	/**
	 * A method to parse the input CVSS input files, containing CVSS impact values for the nodes in the attack graph. 
	 * @param fileName contains the file-path + file-name of the input file.
	 * @param nodes is the ArrayList<Node> that contains information about the entire attack graph. 
	 */
	
	@SuppressWarnings("resource")
	public void fileParser(String fileName, ArrayList<Node> nodes) 
	{
		try{					
			/*
			 *  Open the file that is mentioned in the file (Along with the path)
			 */
			FileInputStream fstream = new FileInputStream(fileName);
			// Get the object of DataInputStream
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));			  
			String strLine;					
			strLine = br.readLine();
			while(!strLine.equalsIgnoreCase("END"))
			{				
				lineNumber++;
				strLine = strLine.replaceAll(" ", "");				
				if(strLine.contains("#"))
				{
					strLine = strLine.replace("#", "");
//					System.out.println(lineNumber + ": Comment: " + strLine);
				}
				else if(strLine.equalsIgnoreCase("START"))
				{
//					System.out.println(lineNumber + ": " + strLine);
				}
				else
				{
					if(!strLine.contains(":"))
						throw new IOException("Invalid Syntax");
					strLine = strLine.replace("[", "").replace("]", "");
					String[] input = strLine.split(":");
					int c, i, a;
					String[] temp = input[1].split(",");
					if(temp.length != 3)
						throw new IOException("Invalid Syntax");
					c = Integer.parseInt(temp[0]);
					i = Integer.parseInt(temp[1]);
					a = Integer.parseInt(temp[2]);
					for(int j=0; j<nodes.size(); j++)
					{
						if(nodes.get(j).getName().equals(input[0]))
						{
							nodes.get(j).setImpacts(c, i, a);
						}
					}
				}
				strLine = br.readLine();
			}
			br.close();
		}
		catch(Exception e)
		{
			System.out.println("Encountered error while parsing file at line: " + lineNumber);
			System.out.println("Error: " + e);
		}
	}

}

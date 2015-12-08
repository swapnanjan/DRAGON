package parser;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class CVSSPreferenceParser {

	/**
	 * A method to parse the CVSS preference file, which outlines, the preferences put forward by the System Administrator(s)
	 * @param filename is the complete file-path + file name, to the input file.
	 * @return a ArrayList<ArrayList<Integer> containing the <C,I,A> formulation for each input.  
	 */
	public ArrayList<ArrayList<Integer>> parsePreference(String filename)
	{		
		
		ArrayList<ArrayList<Integer>> allPreferences = new ArrayList<ArrayList<Integer>>();
		ArrayList<Integer> cia_values = new ArrayList<Integer>(); 
		
		int lineNumber = 0;
		try{					
			/*
			 *  Open the file that is mentioned in the file (Along with the path)
			 */
			FileInputStream fstream = new FileInputStream(filename);
			// Get the object of DataInputStream
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));			  
			String strLine;					
			strLine = br.readLine();						
			while(strLine != null)
			{
				
				lineNumber++;
//				System.out.println("Line" + lineNumber + ": " + strLine);
				String[] cia = strLine.split(",");
				/**
				 * Getting the valation of 1 input <C,I,A>
				 */
				cia_values.add(Integer.parseInt(cia[0]));
				cia_values.add(Integer.parseInt(cia[1]));
				cia_values.add(Integer.parseInt(cia[2]));
				
				/**
				 * Forming the preference order over all the input valuations
				 */
				
				allPreferences.add(new ArrayList<Integer>(cia_values));
				
				/**
				 * Clearing out the stored <C,I,A> valuation for next input
				 */
				cia_values.clear();								
				strLine = br.readLine();
			}			
			br.close();
			}catch(Exception e){
				System.out.println("Encountered error while parsing file at line: " + lineNumber);
				System.out.println("Error: " + e);
				
			}	
		return allPreferences;
	}
}

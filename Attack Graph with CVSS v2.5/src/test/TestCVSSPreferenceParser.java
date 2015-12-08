package test;

import java.io.File;
import java.util.ArrayList;

import parser.CVSSPreferenceParser;

public class TestCVSSPreferenceParser {

	/**
	 * A method to test the CVSS Preference Parser.
	 */
	public static void main(String[] args) {

		CVSSPreferenceParser cpp = new CVSSPreferenceParser();
		ArrayList<ArrayList<Integer>> preferences = cpp.parsePreference("CVSSPreferences" + File.separator + "Model2.txt");
		System.out.println("The preferred valuations in order: ");
		int count = 0;
		for(ArrayList<Integer> cia : preferences)
		{
			System.out.println(++count + ") " + cia);
		}

	}

}

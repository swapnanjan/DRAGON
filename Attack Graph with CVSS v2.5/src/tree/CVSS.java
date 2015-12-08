package tree;

public class CVSS {

	/**
	 * Variables to store the CVSS impact metrics (Confidentiality, Integrity, and Availability) 
	 */
	private int c;
	private int i;
	private int a;
	
	/**
	 * Default constructor of CVSS, C, I and A are all initialized with 1.
	 */
	public CVSS()
	{
		this.c = 1;
		this.i = 1;
		this.a = 1;
	}
	
	/**
	 * Parametirized constructor for CVSS
	 * @param c_input is of type int and sets the CVSS Confidentiality Impact
	 * @param i_input is of type int and sets the CVSS Integrity Impact
	 * @param a_input is of type int and sets the CVSS Availability Impact
	 */
	public CVSS(int c_input, int i_input, int a_input)
	{
		this.c = c_input;
		this.i = i_input;
		this.a = a_input;
	}
	
	/**
	 * Method to set the Confidentiality Impact
	 * @param c_input is of type int and sets the CVSS Confidentiality Impact
	 */
	public void setC(int c_input)
	{
		this.c = c_input;
	}
	
	/**
	 * Method that returns the Confidentiality Impact value
	 * @return c is of type int and returns the CVSS Confidentiality Impact value
	 */
	public int getC()
	{
		return c;
	}
	
	/**
	 * Method to set the Integrity Impact
	 * @param i_input is of type int and sets the CVSS Integrity Impact
	 */
	public void setI(int i_input)
	{
		this.i = i_input;
	}
	
	/**
	 * Method that returns the Integrity Impact value
	 * @return i is of type int and returns the CVSS Integrity Impact value
	 */
	public int getI()
	{
		return i;
	}
	
	
	/**
	 * Method to set the Availability Impact
	 * @param c_input is of type int and sets the CVSS Availability Impact
	 */
	public void setA(int a_input)
	{
		this.a = a_input;
	}
	
	/**
	 * Method that returns the Availability Impact value
	 * @return a is of type int and returns the CVSS Availability Impact value
	 */
	public int getA()
	{
		return a;
	}
	
}

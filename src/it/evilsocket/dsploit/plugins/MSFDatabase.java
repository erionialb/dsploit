package it.evilsocket.dsploit.plugins;

import it.evilsocket.dsploit.net.Target.Exploit;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;



public class MSFDatabase 
{	
	
	
	//Search by cve
	public static Exploit search_by_cve( String query )
	{
		String msfdb_cve_result = "";
		String location = null;
		URLConnection  connection = null;
		Exploit ex;
		
		try
		{
			URL obj = new URL("http://www.metasploit.com/modules/framework/search?cve=" + query);
			connection = obj.openConnection();
			
			location = connection.getHeaderField("Location");
			
			if (location == null) {
				return null;
			}
			int i = location.indexOf("/modules/");
			
			if(i==0)
				return null;
			
			msfdb_cve_result = location.substring(i+9);
		
		}	
			
		catch( MalformedURLException mue )
		{
			mue.printStackTrace();
		}
		catch( IOException ioe )
		{
			ioe.printStackTrace();
		}
		
		ex = new Exploit();
		ex.url = location;
		ex.msf_name = msfdb_cve_result;
		ex.name = msfdb_cve_result.substring(msfdb_cve_result.lastIndexOf("/")+1);
		return ex;
	
	}
	
	
		//Search by osvdb
		public static Exploit search_by_osvdb( int data )
		{
			String msfdb_osvdb_result = "";
			URLConnection  connection = null;
			Exploit ex;
			String location = null;
			
			try
			{
				
				URL obj = new URL("http://www.metasploit.com/modules/framework/search?osvdb=" + data);
				connection = obj.openConnection();
				
				location = connection.getHeaderField("Location");
				
				if (location == null) {
					return null;
				}
				int i = location.indexOf("/modules/");
				
				if(i==0)
					return null;
				
				msfdb_osvdb_result = location.substring(i+9);
			
			}	
				
			catch( MalformedURLException mue )
			{
				mue.printStackTrace();
			}
			catch( IOException ioe )
			{
				ioe.printStackTrace();
			}
			
			ex = new Exploit();
			ex.url = location;
			ex.msf_name = msfdb_osvdb_result;
			ex.name = msfdb_osvdb_result.substring(msfdb_osvdb_result.lastIndexOf("/")+1);
			return ex;
		
		}
	
	
}


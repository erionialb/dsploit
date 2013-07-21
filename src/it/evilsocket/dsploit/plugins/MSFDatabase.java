package it.evilsocket.dsploit.plugins;

import it.evilsocket.dsploit.net.Target.Exploit;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class MSFDatabase 
{	
	private static Exploit search( String encoded_query )
	{
		String msfdb_osvdb_result = "";
		URLConnection  connection = null;
		Exploit ex = null;
		String location = null;
		
		try
		{
			
			URL obj = new URL("http://www.metasploit.com/modules/framework/search?" + encoded_query);
			connection = obj.openConnection();
			
			location = connection.getHeaderField("Location");
			
			if (location == null) {
				return null;
			}
			int i = location.indexOf("/modules/");
			
			if(i<0)
				return null;
			
			msfdb_osvdb_result = location.substring(i+9);
			ex = new Exploit();
			ex.url = location;
			ex.msf_name = msfdb_osvdb_result;
			ex.name = msfdb_osvdb_result.substring(msfdb_osvdb_result.lastIndexOf("/")+1);
		}
		catch( MalformedURLException mue )
		{
			mue.printStackTrace();
		}
		catch( IOException ioe )
		{
			ioe.printStackTrace();
		}
		return ex;
	}
	
	//Search by cve
	public static Exploit search_by_cve( String query )
	{
		return search("cve="+query);
	}
	
	
	//Search by osvdb
	public static Exploit search_by_osvdb( int data )
	{
		return search("osvdb=" + data);
	}
	
	
}


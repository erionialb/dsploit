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
		String query = null;
		URLConnection  connection = null;
		Exploit ex = null;
		String new_location = null;
		
		try
		{
			query = "http://www.metasploit.com/modules/framework/search?" + encoded_query;
			URL obj = new URL(query);
			connection = obj.openConnection();
			connection.getHeaderField("Location"); // this will resolve connection
			new_location = connection.getURL().toString(); 
			
			if (new_location.equals(query)) {
				return null;
			}
			int i = new_location.indexOf("/modules/");
			
			if(i<0)
				return null;
			
			ex = new Exploit();
			ex.url = new_location;
			ex.msf_name = new_location.substring(i+9);
			ex.name = ex.msf_name.substring(ex.msf_name.lastIndexOf("/")+1);
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


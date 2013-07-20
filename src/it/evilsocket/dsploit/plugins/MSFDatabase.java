package it.evilsocket.dsploit.plugins;

import it.evilsocket.dsploit.net.Target.Vulnerability.MsfExploit;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;



public class MSFDatabase 
{	
	
	
	//Search by cve
	public static MsfExploit search_by_cve( String query )
	{
		String msfdb_cve_result = "";
		String location = null;
		URLConnection  connection = null;
		MsfExploit ex;
				
		try
		{
			query = "cve=" + URLEncoder.encode( query, "UTF-8" );
		}
		catch( UnsupportedEncodingException e )
		{
			query = "cve=" + URLEncoder.encode( query );
		}
		
		try
		{
			URL obj = new URL("http://www.metasploit.com/modules/framework/search?" + query);
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
		
		ex = new MsfExploit();
		ex.url = location;
		ex.msf_name = msfdb_cve_result;
		ex.name = msfdb_cve_result.substring(msfdb_cve_result.lastIndexOf("/")+1);
		return ex;
	
	}
	
	
		//Search by osvdb
		public static MsfExploit search_by_osvdb( int data )
		{
			String msfdb_osvdb_result = "";
			String query;
			URLConnection  connection = null;
			MsfExploit ex;
			String location = null;
			
			query = "osvdb=" + data; 
			
			try
			{
				query = URLEncoder.encode( query, "UTF-8" );
			}	
			catch( UnsupportedEncodingException e )
			{
				query = URLEncoder.encode( query );
			}
			
			try
			{
				
				URL obj = new URL("http://www.metasploit.com/modules/framework/search?" + query);
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
			
			ex = new MsfExploit();
			ex.url = location;
			ex.msf_name = msfdb_osvdb_result;
			ex.name = msfdb_osvdb_result.substring(msfdb_osvdb_result.lastIndexOf("/")+1);
			return ex;
		
		}
	
	
}


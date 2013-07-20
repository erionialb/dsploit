package it.evilsocket.dsploit.plugins;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;



public class MSFDatabase 
{	
	
	
	//Search by cve
	public static String search_by_cve( String query )
	{
		String msfdb_cve_result = "";
		URLConnection  connection = null;
				
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
			
			String location = connection.getHeaderField("Location");
			
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
		
		return msfdb_cve_result;
	
	}
	
	
		//Search by osvdb
		public static String search_by_osvdb( int data )
		{
			String msfdb_osvdb_result = "";
			String query;
			URLConnection  connection = null;
					
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
				
				String location = connection.getHeaderField("Location");
				
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
			
			return msfdb_osvdb_result;
		
		}
	
	
}


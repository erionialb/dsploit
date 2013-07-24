package it.evilsocket.dsploit.plugins;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.evilsocket.dsploit.net.Target.Exploit;

public class EXDatabase
{
	private final static Pattern EX_PATTERN = Pattern.compile( "<td class=\"list_explot_description\"[^>]*><a href=\"([^\"]+)\">([^<]+)",		Pattern.MULTILINE | Pattern.DOTALL );
	
	private static ArrayList<Exploit> search(String query)
	{
		ArrayList<Exploit> upshots = new ArrayList<Exploit>();
		Exploit exp;
		URLConnection  connection = null;
		BufferedReader reader	  = null;
		String		   line       = null,
					   body		  = "";
		
		try
		{
			Matcher 		  matcher	  = null;
			
			connection = new URL( "http://www.exploit-db.com/search/?" + query ).openConnection();
			reader	   = new BufferedReader( new InputStreamReader( connection.getInputStream() ) );
			
			while( ( line = reader.readLine() ) != null )
			{
				body += line;
			}
			
			reader.close();
			if((matcher = EX_PATTERN.matcher(body)) != null)
			{
				while(matcher.find())
				{
					exp = new Exploit();
					exp.name = matcher.group(2);
					exp.url = matcher.group(1);
					upshots.add(exp);
				}
			}
			
		}
		catch( MalformedURLException mue )
		{
			mue.printStackTrace();
		}
		catch( IOException ioe ) // 404
		{
			return null;
			//ioe.printStackTrace();
		}
		
		return upshots;
	}
	
	public static ArrayList<Exploit> search_by_osvdb( int id )
	{
		try
		{
			return search("action=search&filter_osvdb=" + URLEncoder.encode( Integer.toString(id), "UTF-8" ));
		}
		catch( UnsupportedEncodingException e )
		{
			return search("action=search&filter_osvdb="+ URLEncoder.encode( Integer.toString(id) ));
		}
	}
	
	public static ArrayList<Exploit> search_by_cveid( String id )
	{
		try
		{
			return search("action=search&filter_cve=" + URLEncoder.encode( id, "UTF-8" ));
		}
		catch( UnsupportedEncodingException e )
		{
			return search("action=search&filter_cve="+ URLEncoder.encode( id ));
		}
	}
}
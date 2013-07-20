package it.evilsocket.dsploit.plugins;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.evilsocket.dsploit.net.Target.Vulnerability.Exploit;

public class EXDatabase
{
	private final static Pattern EX_PATTERN = Pattern.compile( "<tr class=\"list_explot_description\">[^<]*<a href=\"([^\"]+)\">([^<]+)",		Pattern.MULTILINE | Pattern.DOTALL );
	
	public static ArrayList<Exploit> search_by_osvdb( int id )
	{
		ArrayList<Exploit> upshots = new ArrayList<Exploit>();
		
		URLConnection  connection = null;
		BufferedReader reader	  = null;
		String		   line       = null,
					   body		  = "";

		String query;
		Exploit exp;
		
		//<a href="http://www.exploit-db.com/exploits/26517">Microsoft Office PowerPoint 2007 - Crash PoC</a>
		
		query = "action=search&filter_exploit_text=" + id; //the query that defines the string after the ? 
		
		try
		{
			query = URLEncoder.encode( query, "UTF-8" );
		}
		catch( UnsupportedEncodingException e )
		{
			query = URLEncoder.encode( query );
		}
		
		//http://www.exploit-db.com/search/?action=search&filter_exploit_text=%27
			
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
					exp.name = matcher.group(1);
					exp.url = matcher.group(2);
					upshots.add(exp);
				}
			}
			
		}
		catch( MalformedURLException mue )
		{
			mue.printStackTrace();
		}
		catch( IOException ioe )
		{
			ioe.printStackTrace();
		}
		
		return upshots;
	}
}
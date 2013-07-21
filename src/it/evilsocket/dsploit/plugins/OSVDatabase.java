/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package it.evilsocket.dsploit.plugins;

import it.evilsocket.dsploit.net.Target.Vulnerability;

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

import android.util.Log;

public class OSVDatabase 
{	
	private final static Pattern ID_PATTERN       = Pattern.compile( "<a href=\"/show/osvdb/([0-9]+)",		Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern SUMMARY_PATTERN  = Pattern.compile( "[0-9]{4}-[0-9]{2}-[0-9]{2}</td><td>(<a[^>]*>)?([^<]+)",		Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern DESC_PATTERN  	  = Pattern.compile( "<p id=\"desc[0-9]+\"[^>]+>([^<]*)",	Pattern.MULTILINE | Pattern.DOTALL );
	//private final static Pattern SEVERITY_PATTERN = Pattern.compile( "<td[^>]+>([0-9]{1,2}\\.[0-9])?</td>",	Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern PAGES_PATTERN	  = Pattern.compile("<div class=\"pagination\">((?!</div>).)+", Pattern.MULTILINE | Pattern.DOTALL);
	private final static Pattern PAGE_NUMS		  = Pattern.compile("page=([0-9]+)", Pattern.MULTILINE | Pattern.DOTALL);
	private final static String  APPEND_REQUEST   = "&search[text_type]=alltext&search[s_date]=&search[e_date]=&search[refid]=&search[referencetypes]=&search[vendors]=&search[cvss_score_from]=&search[cvss_score_to]=&search[cvss_av]=*&search[cvss_ac]=*&search[cvss_a]=*&search[cvss_ci]=*&search[cvss_ii]=*&search[cvss_ai]=*&kthx=search";
	
	private static ArrayList<Vulnerability> parse_body(String body)
	{
		ArrayList<String> identifiers = new ArrayList<String>(),
						  summaries	  = new ArrayList<String>(),
						  descriptions= new ArrayList<String>(),
						  severities  = new ArrayList<String>();
		ArrayList<Vulnerability> vulns = new ArrayList<Vulnerability>();
		Matcher matcher = null;
		Vulnerability osv;
		
		if( ( matcher = ID_PATTERN.matcher(body) ) != null )
		{
			while( matcher.find() )
			{
				identifiers.add( matcher.group(1) );
			}
			
			if( ( matcher = SUMMARY_PATTERN.matcher(body) ) != null )
			{
				while( matcher.find() )
				{
					summaries.add( matcher.group(matcher.groupCount()) );
				}
				if((matcher = DESC_PATTERN.matcher(body)) != null)
				{
					while(matcher.find())
					{
						descriptions.add(matcher.group(1));
					}
					/* TODO: use cookies and Ajax for get ranking...
					if( ( matcher = SEVERITY_PATTERN.matcher(body) ) != null )
					{
						while( matcher.find() )
						{
							severities.add( matcher.group(1) );
						}									
					}
					*/
				}
			}
		}
		if(identifiers.size() != summaries.size() || summaries.size() != descriptions.size() /*|| descriptions.size() != severities.size()*/)
		{
			Log.d("OSVDatabase","sizemismatch - "+identifiers.size()+" "+summaries.size()+" "+descriptions.size()+" "+severities.size());
			return null;
		}
		for(int i = 0;i<identifiers.size();i++)
		{
			osv = new Vulnerability();
			osv.from_osvdb(Integer.parseInt(identifiers.get(i)),0.0/*Double.parseDouble(severities.get(i))*/,summaries.get(i)+" - "+descriptions.get(i));
			vulns.add(osv);
		}
		return vulns;
	}
	
	private static int get_lastpage_index(String body)
	{
		Matcher matcher = null;
		String tmp;
		int i,j;
		
		if((matcher = PAGES_PATTERN.matcher(body)) == null || !matcher.matches())
			return 0;
		tmp = matcher.group(1);
		if((matcher = PAGE_NUMS.matcher(tmp)) == null)
			return 0;
		i=0;
		while(matcher.find())
			if((j=Integer.parseInt(matcher.group(1))) > i)
				i=j;
		return i;
	}
	
	private static String get_response(String query, int page) throws IOException
	{
		String line,body;
		URLConnection connection;
		BufferedReader reader;
		body = "";
		
		if(page>0)
			connection = new URL( "http://osvdb.org/search/search?" + query + "&page=" + page ).openConnection();
		else
			connection = new URL( "http://osvdb.org/search/search?" + query ).openConnection();
		reader = new BufferedReader( new InputStreamReader( connection.getInputStream() ) );
		while( ( line = reader.readLine() ) != null )
		{
			body += line;
		}
		
		reader.close();
		
		return body;
	}
	
	public static ArrayList<Vulnerability> search( String query )
	{
		ArrayList<Vulnerability> results = new ArrayList<Vulnerability>();
		String		   body		  = "";
		int cur_page,last_page;
		
		try
		{
			query = "search[vuln_title]=" + URLEncoder.encode( query, "UTF-8" ) + APPEND_REQUEST;
		}
		catch( UnsupportedEncodingException e )
		{
			query = "search[vuln_title]=" + URLEncoder.encode( query ) + APPEND_REQUEST;
		}
		Log.d("OSVDatabase","query = \""+query+"\"");
		try
		{
			cur_page=0;
			body = get_response(query, cur_page);
			last_page = get_lastpage_index(body);
			Log.d("OSVDatabase","last_index = "+last_page);
			results.addAll(parse_body(body));
			cur_page++;
			while(cur_page<last_page)
			{
				body=get_response(query, cur_page++);
				results.addAll(parse_body(body));
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
		
		return results;
	}
}

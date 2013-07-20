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
import java.util.Collections;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OSVDatabase 
{	
	private final static Pattern VULN_PATTERN     = Pattern.compile( "<tr class=\"[oe][dv][de]n?\">(.(?!<tr class=\"[oe][dv][de]\"))+",		Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern ID_PATTERN       = Pattern.compile( "<a href=\"/show/osvdb/([0-9]+)",		Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern SUMMARY_PATTERN  = Pattern.compile( "<td>([^<]+)</td></tr>",				Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern SUMMARY2_PATTERN = Pattern.compile( "<td><a[^>]+>([^<]+)</a></td></tr>",	Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern DESC_PATTERN  	  = Pattern.compile( "<p id=\"desc[0-9]+\"[^>]+>([^<]+)",	Pattern.MULTILINE | Pattern.DOTALL );
	private final static Pattern SEVERITY_PATTERN = Pattern.compile( "<td[^>]+>[0-9]{1,2}\\.[0-9]</td>",	Pattern.MULTILINE | Pattern.DOTALL );
	private final static String  APPEND_REQUEST   = "&search[text_type]=alltext&search[s_date]=&search[e_date]=&search[refid]=&search[referencetypes]=&search[vendors]=&search[cvss_score_from]=&search[cvss_score_to]=&search[cvss_av]=*&search[cvss_ac]=*&search[cvss_a]=*&search[cvss_ci]=*&search[cvss_ii]=*&search[cvss_ai]=*&kthx=search";
	
	public static ArrayList<Vulnerability> search( String query )
	{
		ArrayList<Vulnerability> results = new ArrayList<Vulnerability>();
		URLConnection  connection = null;
		BufferedReader reader	  = null;
		String		   line       = null,
					   body		  = "";
		int osvdb_id;
		String desc;
		double severity;
				
		try
		{
			query = "search[vuln_title]=" + URLEncoder.encode( query, "UTF-8" ) + APPEND_REQUEST;
		}
		catch( UnsupportedEncodingException e )
		{
			query = "search[vuln_title]=" + URLEncoder.encode( query ) + APPEND_REQUEST;
		}
		
		try
		{
			Matcher 		  matcher	  = null;		
			ArrayList<String> 	vulns = new ArrayList<String>();
			Vulnerability osv;
			
			connection = new URL( "http://osvdb.org/search/search?" + query ).openConnection();
			reader	   = new BufferedReader( new InputStreamReader( connection.getInputStream() ) );
			
			while( ( line = reader.readLine() ) != null )
			{
				body += line;
			}
			
			reader.close();
			if((matcher = VULN_PATTERN.matcher(body)) != null)
			{
				while(matcher.find())
					vulns.add(matcher.group(1));
			}
			
			for ( String vuln : vulns)
			{
				osvdb_id  = Integer.parseInt(ID_PATTERN.matcher(vuln).group(1));
				if((matcher = SUMMARY_PATTERN.matcher(vuln)) != null)
				{
					desc = matcher.group(1);
				}
				else
				{
					desc = SUMMARY2_PATTERN.matcher(vuln).group(1); 
				}
				if((matcher = DESC_PATTERN.matcher(vuln)) != null)
				{
					//TODO: test if a " - " goes well in graphics.
					desc += " - " + matcher.group(1);
				}
				if((matcher = SEVERITY_PATTERN.matcher(vuln)) != null)
				{
					severity = Double.parseDouble(matcher.group(1));
				}
				else
				{
					severity = 0.0;
				}
				osv = new Vulnerability();
				osv.from_osvdb(osvdb_id,severity,desc);
				results.add(osv);
			}
			
			Collections.sort( results, new Comparator<Vulnerability>(){
			    public int compare( Vulnerability o1, Vulnerability o2 ) {
			        if( o1.getSeverity() > o2.getSeverity() )
			        	return -1;
			        
			        else if( o1.getSeverity() < o2.getSeverity() )
			        	return 1;
			        
			        else 
			        	return 0;
			    }
			});
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

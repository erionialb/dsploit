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
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.evilsocket.dsploit.net.Target.Exploit;

public class EXDatabase
{
	private final static Pattern EX_PATTERN = Pattern.compile( "<td class=\"list_explot_description\"[^>]*><a href=\"([^\"]+)\">([^<]+)",		Pattern.MULTILINE | Pattern.DOTALL );
	@SuppressWarnings("serial")
	private final static HashMap< String, Integer> os_values = new HashMap<String, Integer>() {
		{
			put("aix", 1);
			put("arm", 46);
			put("asp", 2);
			put("atheos", 54);
			put("beos", 51);
			put("bsd", 3);
			put("bsd/ppc", 4);
			put("bsd/x86", 5);
			put("bsdi/x86", 6);
			put("cfm", 47);
			put("cgi", 7);
			put("freebsd", 8);
			put("freebsd/x86", 9);
			put("freebsd/x86-64", 10);
			put("generator", 11);
			put("hardware", 12);
			put("hp-ux", 13);
			put("immunix", 52);
			put("irix", 14);
			put("java", 50);
			put("jsp", 15);
			put("lin/amd64", 17);
			put("lin/x86", 21);
			put("lin/x86-64", 22);
			put("linux", 16);
			put("linux/mips", 18);
			put("linux/ppc", 19);
			put("linux/sparc", 20);
			put("minix", 23);
			put("multiple", 24);
			put("netbsd/x86", 25);
			put("netware", 48);
			put("novell", 26);
			put("openbsd", 27);
			put("openbsd/x86", 28);
			put("os-x/ppc", 29);
			put("osx", 30);
			put("palm os", 53);
			put("php", 31);
			put("plan9", 32);
			put("qnx", 33);
			put("sco", 34);
			put("sco/x86", 35);
			put("sh4", 49);
			put("solaris", 36);
			put("solaris/sparc", 37);
			put("solaris/x86", 38);
			put("tru64", 39);
			put("ultrix", 40);
			put("unix", 41);
			put("unixware", 42);
			put("win32", 43);
			put("win64", 44);
			put("windows", 45);
		}
	};
	
	
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
	
	public static ArrayList<Exploit> search_by_cveid( String id, String os)
	{
		String query = "action=search&filter_cve=";
		String tmp;
		try
		{
			query += URLEncoder.encode( id, "UTF-8" );
		}
		catch( UnsupportedEncodingException e )
		{
			query += URLEncoder.encode( id );
		}
		
		// no encoding here....it's a number
		if(os!=null&&!os.isEmpty()&&os_values.containsKey((tmp = os.toLowerCase(Locale.US))))
			query+="&filter_platform="+Integer.toString(os_values.get(tmp));
		return search(query);
	}
	
	public static ArrayList<Exploit> search_by_osvdb( int id, String os)
	{
		String query = "action=search&filter_osvdb=";
		String tmp;
		try
		{
			query += URLEncoder.encode( Integer.toString(id), "UTF-8" );
		}
		catch( UnsupportedEncodingException e )
		{
			query += URLEncoder.encode( Integer.toString(id) );
		}
		
		// no encoding here....it's a number
		if(os!=null&&!os.isEmpty()&&os_values.containsKey((tmp = os.toLowerCase(Locale.US))))
			query+="&filter_platform="+Integer.toString(os_values.get(tmp));
		return search(query);
	}
}
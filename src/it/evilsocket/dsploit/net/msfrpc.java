package it.evilsocket.dsploit.net;

import it.evilsocket.dsploit.core.System;

import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.msgpack.MessagePack;
import org.msgpack.packer.Packer;
import org.msgpack.type.Value;
import org.msgpack.unpacker.Unpacker;
import org.msgpack.unpacker.Converter;

import android.util.Log;

//TODO: add license and write down that we had taken part of this code from armitage

@SuppressWarnings("rawtypes")
public class msfrpc
{
	private URL u;
	private URLConnection huc;
	private String token;
	private MessagePack msgpack;	
	private Map callCache = new HashMap();
	private final static String TAG = "MSFRPC";
	private final Lock lock = new ReentrantLock();
	private Thread connector;
	public static boolean daemonRunning,loggedIn;
	
	public msfrpc(final String host, final String username, final String password, final int port, boolean ssl) throws MalformedURLException
	{
		if (ssl) { // Install the all-trusting trust manager & HostnameVerifier
			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, new TrustManager[] {
					new X509TrustManager() {
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}
						public void checkClientTrusted(
							java.security.cert.X509Certificate[] certs, String authType) {
						}
						public void checkServerTrusted(
							java.security.cert.X509Certificate[] certs, String authType) {
						}
					}
				}, new java.security.SecureRandom());

				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier( new HostnameVerifier() {
					public boolean verify(String string,SSLSession ssls) {
						return true;
					}
				});
			}
			catch (Exception e) {
			}
			u = new URL("https", host, port, "/api/");
		}
		else {
			u = new URL("http", host, port, "/api/");
		}
		
		msgpack = new MessagePack();
		
		connector = new Thread(new Runnable() {
			@Override
			public void run() {
				try
				{
				while(!(daemonRunning = isDaemonRunning(host, port)))
					Thread.sleep(500);
				while(!(loggedIn = login(username,password)))
					Thread.sleep(500);
				}
				catch ( Exception ex)
				{
					return;
				}
			}
		});
		
		connector.start();
	}
	
	private boolean login ( String username, String password) 
	{
		try
		{
			/* login to msf server */
			Map results = exec("auth.login",new Object[]{ username, password });
	
			/* save the temp token (lasts for 5 minutes of inactivity) */
			token = results.get("token").toString();
	
			/* generate a non-expiring token and use that */
			results = exec("auth.token_generate", new Object[]{ token });
			token = results.get("token").toString();
			return true;
		}
		catch ( Exception ex)
		{
			return false;
		}
	}
	
	public static boolean isDaemonRunning(String host, int port)
	{
		Socket socket = new Socket();
		try
		{
			socket.connect(new InetSocketAddress(host, port), 100);
			socket.close();
			return true;
		}
		catch ( Exception ex)
		{
			return false;
		}
	}
	
	public static boolean startDaemon()
	{
		try
		{
			String 			chroot_path	= System.getSettings().getString("MSF_CHROOT_PATH", "/data/gentoo");
			Process 		process		= new ProcessBuilder().command("su").start();
			DataOutputStream writer  = null;
					
			writer = new DataOutputStream( process.getOutputStream() );
			
			writer.writeBytes("chroot \"" + chroot_path + "\" /bin/su\n");
			writer.flush();
			writer.writeBytes("msfrpcd4.4 -P \"" + System.getSettings().getString("MSF_RPC_PSWD", "pswd") + "\" -U \"" + System.getSettings().getString("MSF_RPC_USER", "msf") + "\" -a 127.0.0.1 -n -t Msg\n");
			writer.flush();
			writer.writeBytes("exit\nexit\n");
			writer.flush();
			return (process.waitFor() == 0);
		}
		catch( Exception ex)
		{
			Log.w(TAG, "unable to start msfrpcd.", ex);
			return false;
		}
	}
	
	@SuppressWarnings("unchecked")
	protected Map exec (String methname, Object[] params) {
		try {
			synchronized(this) {
				lock.lock();
				writeCall(methname, params);
				Object response = readResp();
				lock.unlock();
				if (response instanceof Map) {
					return (Map)response;
				}
				else {
					Map temp = new HashMap();
					temp.put("response", response);
					return temp;
				}
			}
		} 
		catch (RuntimeException rex) { 
			throw rex;
		}
		catch (Exception ex) { 
			throw new RuntimeException(ex);
		}
		finally
		{
			lock.unlock();
		}
	}
	
	protected void writeCall(String methodName, Object[] args) throws Exception {
		huc = u.openConnection();
		huc.setDoOutput(true);
		huc.setDoInput(true);
		huc.setUseCaches(false);
		huc.setRequestProperty("Content-Type", "binary/message-pack");
		huc.setReadTimeout(0);
		OutputStream os = huc.getOutputStream();
		Packer pk = msgpack.createPacker(os);
		pk.write(methodName);
		pk.writeArrayBegin(args.length);
		for(int i = 0; i < args.length;i++)
			pk.write(args[i]);
		pk.close();
		os.close();
	}
	

	
	protected Object readResp() throws Exception {
		InputStream is = huc.getInputStream();
		Unpacker unpk = msgpack.createUnpacker(is);
		Value val = unpk.readValue();
		return (new Converter(val)).read(val.getType());
	}
	
	/** Caches certain calls and checks cache for re-executing them.
	 * If not cached or not cacheable, calls exec. */
	@SuppressWarnings("unchecked")
	private Object cacheExecute(String methodName, ArrayList params) {
		if (methodName.equals("module.info") || methodName.equals("module.options") || methodName.equals("module.compatible_payloads") || methodName.equals("core.version")) {
			StringBuilder keysb = new StringBuilder(methodName);

			for(Object o : params)
				keysb.append(o.toString());

			String key = keysb.toString();
			Object result = callCache.get(key);

			if(result != null)
				return result;

			result = exec(methodName, params.toArray());
			callCache.put(key, result);
			return result;
		}
		return exec(methodName, params.toArray());
	}
	
	public Object execute(String method)
	{
		ArrayList<String> tmp = new ArrayList<String>();
		tmp.add(token);
		return cacheExecute(method, tmp);
	}
	
	@SuppressWarnings("unchecked")
	public Object execute(String method, ArrayList args)
	{
		ArrayList local_array;
		
		local_array = (ArrayList)args.clone();
		local_array.add(0, token);
		return cacheExecute(method, local_array);
	}
}
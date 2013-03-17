/**
 * CS255 project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;

class MITMAdminServer implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    
    public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
	MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
	
	m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
	m_engine = engine;
    }

    public void run() {
	System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
	while( true ) {
	    try {
		m_socket = m_serverSocket.accept();

		byte[] buffer = new byte[40960];

		Pattern userPwdPattern =
		    Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
		
		BufferedInputStream in =
		    new BufferedInputStream(m_socket.getInputStream(),
					    buffer.length);

		// Read a buffer full.
		int bytesRead = in.read(buffer);

		String line =
		    bytesRead > 0 ?
		    new String(buffer, 0, bytesRead) : "";

		Matcher userPwdMatcher =
		    userPwdPattern.matcher(line);

		// parse username and pwd
		if (userPwdMatcher.find()) {
		    String password = userPwdMatcher.group(1);
		    //hashNewPwd();
		    // TODO(cs255): authenticate the user
		    boolean authenticated = checkPwd(password);

		    // if authenticated, do the command
		    if( authenticated ) {
			String command = userPwdMatcher.group(2);
			String commonName = userPwdMatcher.group(3);

			doCommand( command );
		    } else {
			sendString("Password does not match.");
		    }
		}
	    }
	    catch( InterruptedIOException e ) {
	    }
	    catch( Exception e ) {
		e.printStackTrace();
	    }
	}
    }
    
    private Boolean checkPwd(String password) {
	String hashed = "";
	String salt = "";
	try {
	    BufferedReader br = new BufferedReader(new FileReader("pwdfile"));
	    hashed = br.readLine();
	    br.close();
	} catch (Exception e) {
	    System.err.println("FAILURE reading file pwdfile:\n" + e);
	}
	return BCrypt.checkpw(password, hashed);
    }
    
    // get rid of this before submitting. creates a new password hash hardcoded.
    private void hashNewPwd() {
	String authPass = "leekspin";
	String salt = BCrypt.gensalt(12); // 10 log rounds... default. strong enough.
	String hashed = BCrypt.hashpw(authPass, salt);
	// write to pwdhash file...
	try {
	    Writer out  = new OutputStreamWriter
	    (new FileOutputStream("pwdFile"), "UTF-8");
	    BufferedWriter w = new BufferedWriter(out);
	    out.write(hashed);
	    out.close();
	} catch (Exception e) {
	    System.err.println("FAILURE:\n" + e);
	}
	System.out.println("SUCCESS");
    }

    private void sendString(final String str) throws IOException {
	PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
	writer.println(str);
	writer.flush();
    }
    
    private void doCommand( String cmd ) throws IOException {
	if (cmd.equals("shutdown")) {
	    System.exit(0);
	} else if (cmd.equals("stats")) {
	    sendString("Looking for stats...");
	    int stats = m_engine.stats;
	    sendString("Number of connections served: " + stats);
	} else {
	    sendString("Command, " + cmd + ", not recognized.");
	    sendString("Valid commands are:\n " +
		       "stats\n"+
		       "shutdown"
		       );
	}
	m_socket.close();
    }

}

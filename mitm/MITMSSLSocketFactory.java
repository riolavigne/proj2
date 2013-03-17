//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

package mitm;

import iaik.asn1.structures.AlgorithmID;
import iaik.x509.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;


/**
 * MITMSSLSocketFactory is used to create SSL sockets.
 *
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 *
 */
public final class MITMSSLSocketFactory implements MITMSocketFactory
{
    // TODO: Why do I need final keyword? It's not working... BLARGH
    final ServerSocketFactory m_serverSocketFactory;
    final SocketFactory m_clientSocketFactory;
    final SSLContext m_sslContext;

    public KeyStore ks = null;

    /*
     *
     * We can't install our own TrustManagerFactory without messing
     * with the security properties file. Hence we create our own
     * SSLContext and initialise it. Passing null as the keystore
     * parameter to SSLContext.init() results in a empty keystore
     * being used, as does passing the key manager array obtain from
     * keyManagerFactory.getInstance().getKeyManagers(). To pick up
     * the "default" keystore system properties, we have to read them
     * explicitly. UGLY, but necessary so we understand the expected
     * properties.
     *
     */

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a fixed CA certificate
     */
    public MITMSSLSocketFactory()
	throws IOException,GeneralSecurityException
    {
	m_sslContext = SSLContext.getInstance("SSL");

	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	final KeyStore keyStore;
	
	if (keyStoreFile != null) {
	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

	    this.ks = keyStore;
	} else {
	    keyStore = null;
	}

	keyManagerFactory.init(keyStore, keyStorePassword);

	m_sslContext.init(keyManagerFactory.getKeyManagers(),
			  new TrustManager[] { new TrustEveryone() },
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory(); 
    }

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a dynamically generated server certificate
     * that contains the specified ed Name.
     */
    public MITMSSLSocketFactory(Principal serverDN, BigInteger serialNumber)
	throws IOException,GeneralSecurityException, Exception
    {
        // Generates a new (forged) server certificate with a DN of serverDN
        // and a serial number of serialNumber.

        // Start by opening local keystore with our certificate
	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	// The "alias" is the name of the key pair in our keystore. (default: "mykey")
	String alias = System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY, "mykey");

	final KeyStore keyStore;
	
	if (keyStoreFile != null) {
	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);
	    
	    this.ks = keyStore;
	} else {
	    keyStore = null;
	}
	
	// Get our key pair and our own DN (not the remote server's DN) from the keystore.
	PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStorePassword); 
	
	// generate our certificate based on the keystore data
	iaik.x509.X509Certificate certificate = new
	    iaik.x509.X509Certificate(keyStore.getCertificate(alias).getEncoded());
	
	// Generate a forged server certificate
	iaik.x509.X509Certificate serverCertificate = 
	    getServerCert(certificate, serverDN, serialNumber, privateKey);
	
	// serverKeyStore used for serverCert - for cleaner code
	KeyStore serverKeyStore = KeyStore.getInstance(keyStoreType);
	// initialize the key store, use same password as for our keystore
	serverKeyStore.load(null, keyStorePassword);
	// create a certificate chain to pass
	java.security.cert.X509Certificate[] certChain = 
	    new java.security.cert.X509Certificate[1];
	certChain[0] = serverCertificate;
	// add our forged certificate to it + private key...
	serverKeyStore.setKeyEntry(alias, privateKey, keyStorePassword, certChain);
	
	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	keyManagerFactory.init(serverKeyStore, keyStorePassword);
        
	m_sslContext = SSLContext.getInstance("SSL");
	
	m_sslContext.init(keyManagerFactory.getKeyManagers(),
	  new TrustManager[] { new TrustEveryone() },
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }
    
    /**
     * Generates a forged certificate by copying the passed in certificate,
     * substituting a date, severDN and serial number, and then signing it.
     */
    private iaik.x509.X509Certificate getServerCert(iaik.x509.X509Certificate ourCert, Principal serverDN, BigInteger serialNumber, PrivateKey pk) {
	try {
	    iaik.x509.X509Certificate serverCert =
		new iaik.x509.X509Certificate(ourCert.getEncoded()); // copy our cert
	    GregorianCalendar cal = new GregorianCalendar(2013, 1, 1);
	    serverCert.setValidNotBefore(cal.getTime());
	    cal.set(2014, 1, 1);
	    serverCert.setValidNotAfter(cal.getTime());
	    serverCert.setSubjectDN(serverDN);
	    serverCert.setSerialNumber(serialNumber);
	    AlgorithmID algo = ourCert.getSignatureAlgorithm();
	    serverCert.sign(algo, pk);
	    return serverCert;

	} catch (Exception e) {
	    System.err.println(e);
	    return null;
	}
    }

    public final ServerSocket createServerSocket(String localHost,
						 int localPort,
						 int timeout)
	throws IOException
    {
	final SSLServerSocket socket =
	    (SSLServerSocket)m_serverSocketFactory.createServerSocket(
								      localPort, 50, InetAddress.getByName(localHost));

	socket.setSoTimeout(timeout);

	socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

	return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)
	throws IOException
    {
	final SSLSocket socket =
	    (SSLSocket)m_clientSocketFactory.createSocket(remoteHost,
							  remotePort);

	socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
	
	socket.startHandshake();

	return socket;
    }

    /**
     * We're carrying out a MITM attack, we don't care whether the cert
     * chains are trusted or not ;-)
     *
     */
    private static class TrustEveryone implements javax.net.ssl.X509TrustManager
    {
	public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
				       String authenticationType) {
	}
	
	public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
				       String authenticationType) {
	}

	public java.security.cert.X509Certificate[] getAcceptedIssuers()
	{
	    return null;
	}
    }
}
    

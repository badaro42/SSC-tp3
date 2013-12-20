package p2;

import sun.security.x509.X500Name;

import javax.net.ssl.*;
import javax.security.cert.CertificateNotYetValidException;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.security.KeyStore;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class AuthServer3 {

	private static final String ADDRESS = "localhost";
	private static final int PORT = 9000;
	private static final String AUTHENTICATION_FILE = "UsersAuth";
	private static final String CONFIG_FILE = "configCS";
	private static final String CONFIG_NETWORKING_FILE = "configNetwork";
	private static final int NONCE_LENGTH = 8;
//    private static final String AUTH_CONFIG_FILE = "authConfig";

	private Map<String, String> users;

	private String cipherSuiteWithKeys;

	private int sessionID = 1; //TODO


	private static final String KEYSTORE_PROVIDER = "JKS";
	private static final String SERVER_CERTIFICATE_PASSWORD = "password";




	private AuthServer3() throws Exception{
		users = new HashMap<String, String>();

		loadUsers();

		initSSL();

		readConfig(CONFIG_FILE);

	}

	private void readConfig(String filename){
		File f = new File(filename);
		try {
			Scanner in = new Scanner(f);

			cipherSuiteWithKeys = "";

			in.nextLine();

			cipherSuiteWithKeys += in.next();	//ciphersuite
			in.nextLine();

			cipherSuiteWithKeys += "+" + in.next();	//hmac
			in.nextLine();

			cipherSuiteWithKeys += "+" + in.next();	//keyBytes
			in.nextLine();

			cipherSuiteWithKeys += "+" + in.next();	//vector init bytes
			in.nextLine();

			cipherSuiteWithKeys += "+" + in.next();	//hmac bytes
			in.nextLine();

			in.close();


			f = new File(CONFIG_NETWORKING_FILE);
			in = new Scanner(f);
			cipherSuiteWithKeys += "+" + in.next();	//address
			cipherSuiteWithKeys += "+" + in.next(); //port
			in.close();


//			cipherSuiteWithKeysBytes = cipherSuiteWithKeys.getBytes();

		} catch (FileNotFoundException e) {
			System.err.println("Config file not found");
//			e.printStackTrace();
			System.exit(0);
		}
	}




//	public static byte[] stringToBytes(String s) {
//		byte[] b2 = new BigInteger(s, 36).toByteArray();
//		return Arrays.copyOfRange(b2, 1, b2.length);
//	}

	private void loadUsers() throws IOException{
		File f = new File(AUTHENTICATION_FILE);

		Scanner sf = new Scanner(f);

		int numUsers = sf.nextInt();
		sf.nextLine();

		String user;
		String pass;
		while( numUsers-- > 0 ){
			user = sf.nextLine();
			pass = sf.nextLine();
			users.put(user, pass);
		}
		sf.close();
	}




	private static final String SERVER_KEY_STORE = "serverks";
	private static final String SERVER_KEY_STORE_PASSWORD = "password";
	private static final String SERVER_KEY_MANAGER = "SunX509";
	private static final String SERVER_TRUST_STORE = "servertruststore";
	private SSLServerSocket serverSock;


	private void waitintClients(){
		while(true){
			SSLSocket socket;
			try {
				socket = (SSLSocket)serverSock.accept();


				Thread t = new Thread( new Authentication(socket) );
				t.run();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}


	private void initSSL(){
		serverSock = null;
		try
		{
			//load server private key
			KeyStore serverKeys = KeyStore.getInstance("JKS");
			serverKeys.load(new FileInputStream(SERVER_KEY_STORE), SERVER_KEY_STORE_PASSWORD.toCharArray());
			KeyManagerFactory serverKeyManager = KeyManagerFactory.getInstance(SERVER_KEY_MANAGER);
			//System.out.println(KeyManagerFactory.getDefaultAlgorithm());
			//System.out.println(serverKeyManager.getProvider());
			serverKeyManager.init(serverKeys,SERVER_CERTIFICATE_PASSWORD.toCharArray());
			//load client public key
			KeyStore clientPub = KeyStore.getInstance("JKS");
			clientPub.load(new FileInputStream(SERVER_TRUST_STORE), SERVER_KEY_STORE_PASSWORD.toCharArray());
			TrustManagerFactory trustManager = TrustManagerFactory.getInstance("SunX509");
			trustManager.init(clientPub);
			//use keys to create SSLSoket
			SSLContext ssl = SSLContext.getInstance("TLS");
			ssl.init(serverKeyManager.getKeyManagers(), trustManager.getTrustManagers(),
					SecureRandom.getInstance("SHA1PRNG"));
			serverSock = (SSLServerSocket)ssl.getServerSocketFactory().createServerSocket(PORT);
			serverSock.setNeedClientAuth(true);

//			String[] cs ={"TLS_RSA_WITH_AES_128_CBC_SHA"};
//			serverSock.setEnabledCipherSuites(cs);

		}
		catch (Exception e){
			e.printStackTrace();
		}

	}


	private class Authentication implements Runnable{
		private static final int PROT_VERSION = 2;

		SSLSocket socket;
		Authentication(SSLSocket socket) throws IOException {
			this.socket = socket;
			verifyCertificates();
		}

		//verifica o certificado do servidor se o CN do host corresponde ao CN do certificado.
		//verifica tambem se ainda se encontra válido à data da conexao
		private void verifyCertificates(){
			try {
				SSLSession session = socket.getSession();
				Principal server = session.getPeerPrincipal();

				String[] rawInfo = server.toString().split(", ");
				String[] cnInfo = rawInfo[0].split("=");

				X509Certificate[] certs = session.getPeerCertificateChain();
				String domain = certs[0].getSubjectDN().getName();
				certs[0].checkValidity(new Date());
				X500Name name = new X500Name(domain);

				if (!cnInfo[1].equals(name.getCommonName()))
					System.err.println("Aviso! Esperava " + cnInfo[1] + " mas encontrei " + name.getCommonName() + "!!");

			} catch (CertificateNotYetValidException e) {
				System.err.println("The certificate has expired");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}



		@Override
		public void run() {

			BufferedReader in = null;
			PrintWriter out = null;
			try {
				in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
				out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(this.socket.getOutputStream())));

				System.out.println(this.socket.isConnected());

				String username = in.readLine();
				String password = in.readLine();

				if (users.get( username ).equals(password) ){
					out.println(cipherSuiteWithKeys);
					out.flush();
				}


			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}




	public static void main(String[] args) {

		AuthServer3 as;
		try{
			as = new AuthServer3();
			as.waitintClients();
		}
		catch(Exception e){
			e.printStackTrace();
			System.exit(0);
		}
	}
}

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import java.security.*;
import javax.net.ssl.*;

public class AuthServer3 {

	private static final String ADDRESS = "224.1.1.0";
	private static final int PORT = 9000;
	private static final String AUTHENTICATION_FILE = "UsersAuth";
	private static final String CONFIG_FILE = "config";
	private static final int NONCE_LENGTH = 8;
//    private static final String AUTH_CONFIG_FILE = "authConfig";

	private Map<String, String> users;

	private byte[] cipherSuiteWithKeys;

	private int sessionID = 1; //TODO


	private static final String KEYSTORE_PROVIDER = "JKS";
	private static final String SERVER_CERTIFICATE_PASSWORD = "password";




	private AuthServer3() throws Exception{
		users = new HashMap<String, String>();

		loadUsers();

		readConfig(CONFIG_FILE);

	}

	private void readConfig(String filename){
		File f = new File(filename);
		try {
			Scanner in = new Scanner(f);

			String s = "";

			in.nextLine();

			s += in.next();	//ciphersuite
			in.nextLine();

			s += "+" + in.next();	//hmac
			in.nextLine();

			s += "+" + in.next();	//keyBytes
			in.nextLine();

			s += "+" + in.next();	//vector init bytes
			in.nextLine();

			s += "+" + in.next();	//hmac bytes
			in.nextLine();

			in.close();

			cipherSuiteWithKeys = s.getBytes();

		} catch (FileNotFoundException e) {
			System.err.println("Config file not found");
//			e.printStackTrace();
			System.exit(0);
		}
	}




	public static byte[] stringToBytes(String s) {
		byte[] b2 = new BigInteger(s, 36).toByteArray();
		return Arrays.copyOfRange(b2, 1, b2.length);
	}

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




	private static final String SERVER_KEY_STORE = "serverkeystore";
	private static final String SERVER_KEY_STORE_PASSWORD = "server";
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
//			socket = (SSLSocket)serverSock.accept();
			//send data
//			out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
//			out.println("Resposta do servidor ....");
//			out.flush();
		}
		catch (Exception e){
			e.printStackTrace();
		}
//		finally{
//
//			if(out!=null) out.close();
//			try{
//
//				if(serverSock!=null) serverSock.close();
////				if(socket!=null) socket.close();
//			}
//			catch (IOException e){
//
//				e.printStackTrace();
//			}
//		}
	}


	private class Authentication implements Runnable{
		private static final int PROT_VERSION = 2;


		private PrintWriter out = null;

		Authentication(SSLSocket socket) throws IOException {
			out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
		}

		private void send(byte[] msg){

			out.println("Resposta do servidor ....");
			out.flush();

		}

		@Override
		public void run() {
//			byte[] buffer = new byte[65536];
//			DatagramPacket dgPacket = new DatagramPacket(buffer, buffer.length);

			//TODO

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

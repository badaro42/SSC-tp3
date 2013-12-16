
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class AuthServer {

	private static final String ADDRESS = "224.1.1.0";
	private static final int PORT = 9000;
	private static final String AUTHENTICATION_FILE = "UsersAuth";
	private static final String CONFIG_FILE = "config";
	private static final int NONCE_LENGTH = 8;
	private static final String AUTH_CONFIG_FILE = "authConfig";
	
	private Map<String, String> users;
	
	private byte[] cipherSuiteWithKeys;
	private String authAlgorithm;
	private int iterationCount;
	private byte[] salt;


	private AuthServer() throws IOException{
		users = new HashMap<String, String>();

		loadUsers();

		readConfig(CONFIG_FILE);
		readAuthAlgorithm(AUTH_CONFIG_FILE);
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
//			// e.printStackTrace();
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

	private void waitingRequests() throws IOException{
		@SuppressWarnings("resource")
		MulticastSocket rs = new MulticastSocket(PORT);;

		InetAddress group = InetAddress.getByName( ADDRESS );

		rs.joinGroup(group);

		byte[] buffer = new byte[65536];
		DatagramPacket p = new DatagramPacket(buffer, buffer.length);

		while(true){
			try{
				rs.receive(p);
			}catch(IOException e){
				continue;
			}


			Thread t = new Thread( new Authentication(p) ); 
			t.run();

		}
		
		
	}
	private void readAuthAlgorithm(String filename){
		File f = new File(filename);
		try {
			Scanner in = new Scanner(f);
//			String s[] = new String[3];
			
			authAlgorithm = in.next(); in.nextLine();
			salt = stringToBytes( in.next() );
			in.nextLine();
			iterationCount = ( new Integer(in.next()) ).intValue();
			in.nextLine();
			
			in.close();
			
		} catch (FileNotFoundException e) {
			System.err.println("authConfig file not found");
//			// e.printStackTrace();
			System.exit(0);
		}
	}

	private class Authentication implements Runnable{
		private static final byte PROT_VERSION = 0x1;

		private byte[] rData;
		private SocketAddress socketAddress;
		private byte[] nonceC;
		private byte[] nonceS;

		DatagramSocket dgsocket;
		
		private Cipher cDec;
		private Cipher cEnc;
		
		private void initCipherSuite(String clientID, String clientPassword) throws 
		NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException{
			
			char[] password = clientPassword.toCharArray();
//	        byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };
//	        int iterationCount = 2048;
	        
	        // Misturar ja o salt e o iterador a usar na geracap da chave
	        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, iterationCount);
	        SecretKeyFactory keyFact = SecretKeyFactory.getInstance( authAlgorithm );
	        
	        cEnc = Cipher.getInstance( authAlgorithm );
	        Key sKey = keyFact.generateSecret(pbeSpec);
	        
	        // Decifrar ja com a chave gerada com base no esquema PBE
	        cEnc.init(Cipher.ENCRYPT_MODE, sKey);
			
	        
	        cDec = Cipher.getInstance( authAlgorithm );
	        cDec.init(Cipher.DECRYPT_MODE, sKey);
		}
		

		Authentication(DatagramPacket packet){
			rData = packet.getData();


			socketAddress = packet.getSocketAddress();

			try {
				dgsocket = new DatagramSocket();
				dgsocket.setSoTimeout(10000);
			} catch (SocketException e1) {
				e1.printStackTrace();
			}

			try {
				cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding","BC");



			} catch (NoSuchAlgorithmException | NoSuchProviderException
					| NoSuchPaddingException e) {
				// e.printStackTrace();
			}
		}
		
		private void sendMsgType2(String clientPassword, byte[] nonceC ){
			
			SecureRandom sr;

			nonceS = new byte[8];

			try {
				sr = SecureRandom.getInstance("SHA1PRNG");
				sr.nextBytes(nonceS);

			} catch (NoSuchAlgorithmException e) {
				// e.printStackTrace();
			}

			nonceC[nonceC.length-1] += 1;		// incrementar nonce
			

			byte[] toSend = new byte[NONCE_LENGTH*2];

			System.arraycopy(nonceS, 0, toSend, 0, NONCE_LENGTH);
			System.arraycopy(nonceC, 0, toSend, NONCE_LENGTH, NONCE_LENGTH);

			
			// Cifrar com chaves pre-calculadas
	        
			try {
	
				byte[] out = cEnc.doFinal(toSend, 0, toSend.length);
				
				toSend = new byte[4 + out.length];
				toSend[0] = PROT_VERSION;
				toSend[1] = 2;
				toSend[2] = (byte) ( (toSend.length - 4) >>> 8) ;
				toSend[3] = (byte) (toSend.length - 4) ;
				
				System.arraycopy(out, 0, toSend, 4, out.length);
				
				
			} catch (Exception e1) {
				e1.printStackTrace();
			} 

			try {
				DatagramPacket p = new DatagramPacket(toSend, toSend.length);
				p.setSocketAddress(socketAddress);

				dgsocket.send( p );
			} catch (IOException e) {
				// e.printStackTrace();
			}

		}

		private String getClientID(){
			int rlength = ((rData[2] << 8) | rData[3]);
			byte[] userBytes = new byte[rlength - 8];

			System.arraycopy(rData, 4, userBytes, 0, rlength-8);
			return new String(userBytes);
		}
	
		private void sendMsgType4() throws IllegalBlockSizeException, BadPaddingException{

			byte[] buffer = new byte[ 12 + cipherSuiteWithKeys.length ];
			System.arraycopy(cipherSuiteWithKeys, 0, buffer, 12, cipherSuiteWithKeys.length);

			//ip multicast
			buffer[4] = (byte)224;
			buffer[5] = 1;
			buffer[6] = 1;
			buffer[7] = 1;

			//multicast port
			buffer[8] = 0b0010_0111;
			buffer[9] = 0b0000_1111;

			//sessionID
			buffer[10] = 0b0001_1111;
			buffer[11] = (byte) 0b1100_0011;
			
			
			byte[] out = cEnc.doFinal(buffer, 4, 8 + cipherSuiteWithKeys.length);
			
			
			buffer = new byte[4 + out.length];
			System.arraycopy(out, 0, buffer, 4, out.length);
			

			buffer[0] = PROT_VERSION;
			buffer[1] = 4;
			
			//tamanho do bloco
			buffer[2] = (byte) ( (out.length) >>> 8) ;
			buffer[3] = (byte) out.length;
			
			
			DatagramPacket p = new DatagramPacket(new byte[1], 1);
			
			
			p.setData(buffer);


			p.setSocketAddress(socketAddress);

			try {
				dgsocket.send(p);
			} catch (IOException e) {
				// e.printStackTrace();
			}

		}

		
		private boolean processType3(){
			byte[] nonceS2 = new byte[NONCE_LENGTH];
			
//			int cipheredLength = ((rData[2] << 8 ) | rData[3] ) & 0xffff;
			byte[] aux = { rData[2], rData[3] };
			int cipheredLength = new BigInteger(1, aux).intValue();
			
			
			try {
				byte[] out = cDec.doFinal(rData, 4, cipheredLength);
				
				System.arraycopy(out, 0, nonceS2, 0, NONCE_LENGTH);
				
				// incrementar nonce
				nonceS[NONCE_LENGTH - 1] += 1;
				if( ! MessageDigest.isEqual(nonceS, nonceS2) ){
					nonceS[NONCE_LENGTH - 1] -= 1;
					return false;
				}
				
				System.arraycopy(out, NONCE_LENGTH, nonceC, 0, NONCE_LENGTH);		
				
			} catch (Exception e) {
				// e.printStackTrace();
			} 		
			return true;
		}

		@Override
		public void run() {

			byte[] buffer = new byte[65536];
			DatagramPacket dgPacket = new DatagramPacket(buffer, buffer.length);

			String clientID;

			if( rData[1] == 1 ) {

				clientID = getClientID();

				int rlength = ((rData[2] << 8) | rData[3]);
				nonceC = new byte[8];
				System.arraycopy(rData, rlength-4, nonceC, 0, 8);

				String clientPassword = users.get(clientID);
				if(clientPassword == null)
					System.exit(0);
				
				try {
					initCipherSuite(clientID, clientPassword);
				} catch (Exception e1) {
					e1.printStackTrace();
					System.exit(0);
				}
				
				sendMsgType2(clientPassword, nonceC );
				
				
				//receive type 3
				try {
					dgsocket.receive(dgPacket);
					rData = dgPacket.getData();

				} catch (IOException e) {
					// e.printStackTrace();
				}

				if(rData[1] == 3){
					if( processType3() )
						try {
							sendMsgType4();
						} catch (IllegalBlockSizeException e) {
							// e.printStackTrace();
						} catch (BadPaddingException e) {
							// e.printStackTrace();
						}

				}
			}
		}
	}

	public static void main(String[] args) {

		AuthServer as;
		try{
			as = new AuthServer();

			try {
				as.waitingRequests();
			} catch (IOException e) {
				// e.printStackTrace();

			}
		}
		catch(IOException e){
			System.out.println("Error reading users authentication file.");
			System.exit(0);
		}
	}
}

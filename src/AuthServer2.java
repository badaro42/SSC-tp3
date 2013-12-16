import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.security.cert.Certificate;


public class AuthServer2 {

	private static final String ADDRESS = "224.1.1.0";
	private static final int PORT = 9000;
	private static final String AUTHENTICATION_FILE = "UsersAuth";
	private static final String CONFIG_FILE = "config";
	private static final int NONCE_LENGTH = 8;
//    private static final String AUTH_CONFIG_FILE = "authConfig";

	private Map<String, String> users;
	private Set<byte[]> nonces;

	private byte[] cipherSuiteWithKeys;
//    private String authAlgorithm;
//    private int iterationCount;
//    private byte[] salt;

	private int sessionID = 1; //TODO

	SecureRandom srNonces; //nonce generator
	MessageDigest md;

//certificado

	private PrivateKey serverPrivKey;
	private static final String KEYSTORE_PROVIDER = "JKS";
	private static final String SERVER_CERTIFICATE_PASSWORD = "password";
	private Cipher serverAsymCipher;

	//carrega a chave privada a partir dum certificado
	private void getKeyFromServerKeystore() {
		char[] password = SERVER_CERTIFICATE_PASSWORD.toCharArray();
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

		KeyStore ks = null;
		FileInputStream input = null;
		String alias = "authserver";
		try {
			ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
			input = new FileInputStream("myKeyStore");
			ks.load(input, password);


			KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
			serverPrivKey = pkEntry.getPrivateKey();

			serverAsymCipher = Cipher.getInstance("RSA", "BC");
			SecureRandom random = UtilsDH.createFixedRandom();

			serverAsymCipher.init(Cipher.DECRYPT_MODE, serverPrivKey, random);


		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	private PublicKey clientPubKey;
	private static final String CLIENT_CERTIFICATE_PASSWORD = "password";
	private static final String CLIENT_CERTIFICATE_FILENAME = "proxycert.cer";
	private Cipher clientAsymCipher;
	//carrega a chave privada a partir dum certificado
	private void getKeyFromClientCertificate() {
		char[] password = CLIENT_CERTIFICATE_PASSWORD.toCharArray();
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

		KeyStore ks = null;
		FileInputStream input = null;
		try {
			ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
			input = new FileInputStream("myKeyStore");
			ks.load(input, password);

			String alias = "proxy";

			Certificate cert = ks.getCertificate(alias);


			Key key = ks.getKey(alias, "password".toCharArray());
			if (key instanceof PrivateKey) {
				// Get certificate of public key
				//Certificate cert = ks.getCertificate(alias);

				// Get public key
//				PublicKey publicKey = cert.getPublicKey();

				clientPubKey = cert.getPublicKey();

				clientAsymCipher = Cipher.getInstance("RSA", "BC");
				SecureRandom random = UtilsDH.createFixedRandom();

				clientAsymCipher.init(Cipher.ENCRYPT_MODE, clientPubKey, random);


				// Return a key pair
//				new KeyPair(publicKey, (PrivateKey) key);
			}

//			KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("ent1", protParam);
//			serverPubKey = pkEntry.getPrivateKey();
//
//			serverAsymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
//			SecureRandom random = UtilsDH.createFixedRandom();
//
//			serverAsymCipher.init(Cipher.ENCRYPT_MODE, serverPubKey, random);


		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	private AuthServer2() throws Exception{
		users = new HashMap<String, String>();
		nonces = new HashSet<byte[]>();

		loadUsers();

		getKeyFromClientCertificate();
		getKeyFromServerKeystore();

		readConfig(CONFIG_FILE);
//        readAuthAlgorithm(AUTH_CONFIG_FILE);

		srNonces = SecureRandom.getInstance("SHA1PRNG");
		md = MessageDigest.getInstance("SHA-1");

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

	private void waitingRequests() throws IOException{
		@SuppressWarnings("resource")
		MulticastSocket rs = new MulticastSocket(PORT);

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
//    private void readAuthAlgorithm(String filename){
//        File f = new File(filename);
//        try {
//            Scanner in = new Scanner(f);
////			String s[] = new String[3];
//
//            authAlgorithm = in.next(); in.nextLine();
//            salt = stringToBytes( in.next() );
//            in.nextLine();
//            iterationCount = ( new Integer(in.next()) ).intValue();
//            in.nextLine();
//
//            in.close();
//
//        } catch (FileNotFoundException e) {
//            System.err.println("authConfig file not found");
//			e.printStackTrace();
//            System.exit(0);
//        }
//    }

	private class Authentication implements Runnable{
		private static final int PROT_VERSION = 2;

		private byte[] rData;
		private SocketAddress socketAddress;
		private byte[] nonceC;
		private byte[] nonceS;

		DatagramSocket dgsocket;
		KeyAgreement sKeyAgree;
		KeyPair sPair;


		private Cipher dfEnc;
		private Cipher dfDec;

		private byte[] dfKey;

		// Parametro para o gerador do Grupo de Cobertura de P
		private BigInteger g512 = new BigInteger(
				"153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7" + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
						+ "410b7a0f12ca1cb9a428cc", 16);

		// Um grande numero primo P
		private BigInteger p512 = new BigInteger(
				"9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387" + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
						+ "f0573bf047a3aca98cdf3b", 16);

		private DHParameterSpec dhParams = new DHParameterSpec(p512, g512);


		KeyPairGenerator keyGen;

//        private Cipher cDec;
//        private Cipher cEnc;



		private void sendMsgType7() throws Exception {
			try{
				nonceC[nonceC.length-1] += 1;	//incrementar nonce
				byte[] key = sPair.getPublic().getEncoded(); //get diffie-helman public key
				nonceS = new byte[NONCE_LENGTH];
				srNonces.nextBytes(nonceS);

				byte[] plainMsg = new byte[nonceC.length + nonceS.length + key.length + 2];
				//bytes para dar o tamanho de Yb
				plainMsg[0] = (byte) ( (key.length ) >>> 8) ;
				plainMsg[1] = (byte) key.length;
				int destPos = 2;

				System.arraycopy(nonceC, 0, plainMsg, destPos, nonceC.length);
				destPos += nonceC.length;
				System.arraycopy(nonceS, 0, plainMsg, destPos, nonceS.length);
				destPos += nonceS.length;
				System.arraycopy(key, 0, plainMsg, destPos, key.length);
				destPos += key.length;
				md.update(plainMsg, 0, plainMsg.length);
				byte[] mHash = md.digest();	//hash para depois cifrar
//			byte[] cipherText = mHash;
				byte[] cipherText = serverAsymCipher.doFinal(mHash);


				byte[] msg = new byte[plainMsg.length + cipherText.length + 4];
				msg = addHeader(msg, PROT_VERSION, 7);

				int msgOffset = 4;
				System.arraycopy(plainMsg, 0, msg, msgOffset, plainMsg.length);
				msgOffset += plainMsg.length;
				System.arraycopy(cipherText, 0, msg, msgOffset , cipherText.length);

//				System.out.println("MSG");
//				for (byte b: msg)
//					System.out.print(b + " ");
//				System.out.println("----");

				DatagramPacket p = new DatagramPacket(msg, msg.length);
				p.setSocketAddress(socketAddress);

				try {
					dgsocket.send( p );
				} catch (IOException e) {
					e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
				}

			} catch (Exception e){
				e.printStackTrace();
			}
		}

		private byte[] addHeader(byte[] msg, int protVersion, int contType){
			msg[0] = (byte)protVersion;
			msg[1] = (byte)contType;
			msg[2] = (byte) ( (msg.length - 4) >>> 8) ;
			msg[3] = (byte) (msg.length - 4) ;
			return msg;
		}


		private byte[] getContent(){
			byte[] aux = { rData[2], rData[3] };
			int contentLength = new BigInteger(1, aux).intValue();
			byte[] content = new byte[contentLength];
			System.arraycopy(rData, 4, content, 0, contentLength);
			return content;
		}

		private int getIntFromBytes(byte[] buf, int offset, int length ){
			byte[] aux = { buf[offset++], buf[offset++]};
			return new BigInteger(1, aux).intValue();
		}

		private void processMsgType6(  ) {
			try{
				byte[] msg = getContent(); //remove headers

//				System.out.println("+++++++++++++");
//				for(byte b: msg)
//					System.out.print(b + " ");
//				System.out.println("+++++++++++++");
				int offset = 0;
				int dfKeyLength = getIntFromBytes(msg, offset, 2);//tamanho da key para o diffie-helman
				offset += 2;
				int usernameHashLength = getIntFromBytes(msg, offset, 2);
				offset += 2;
				int firstCipherSize = getIntFromBytes(msg, offset, 2);
				offset += 2;
				int secontCipherSize = getIntFromBytes(msg, offset, 2);
				offset += 2;

				//obter a chave diffie-helman da mensagem
				byte[] bKey = new byte[dfKeyLength];
				System.arraycopy(msg, offset, bKey, 0, dfKeyLength);
				offset += dfKeyLength;

				//obter o hash do username
				byte[] userHash = new byte[usernameHashLength];
				System.arraycopy(msg, offset, userHash, 0, usernameHashLength);
				offset += usernameHashLength;

				//obter o primeiro conteudo cifrado
				byte[] cipheredWithServerKey = new byte[firstCipherSize];
				System.arraycopy(msg, offset, cipheredWithServerKey, 0, firstCipherSize);
				offset += firstCipherSize;

				//obter o segundo conteudo cifrado
				byte[] cipheredWithUserPrivKey = new byte[secontCipherSize];
				System.arraycopy(msg, offset, cipheredWithUserPrivKey, 0, secontCipherSize);
				byte[] hashPlainData = clientAsymCipher.doFinal(cipheredWithUserPrivKey);


				byte[] firstPlainData = serverAsymCipher.doFinal(cipheredWithServerKey);
				String username = new String(firstPlainData, NONCE_LENGTH, firstPlainData.length - NONCE_LENGTH);
				md.update(username.getBytes());
				byte[] hash = md.digest();
				//comparar hash do username
				if ( ! MessageDigest.isEqual(hash, userHash) )
					return;


				byte[] auxNonce = new byte[NONCE_LENGTH];
				System.arraycopy(firstPlainData, 0, auxNonce, 0, NONCE_LENGTH);
				if (nonces.contains( auxNonce ))
					return;

				nonceC = new byte[NONCE_LENGTH];
				System.arraycopy(firstPlainData, 0, nonceC, 0, NONCE_LENGTH);
				nonces.add( nonceC );


				//hash da password, nonce e Ya
				String password = users.get(username);
				byte[] pwdBytes = password.getBytes();
				byte[] toHash = new byte[NONCE_LENGTH+ dfKeyLength + pwdBytes.length];
				offset = 0;
				System.arraycopy(nonceC, 0, toHash, offset, NONCE_LENGTH);
				offset += NONCE_LENGTH;
				System.arraycopy(bKey, 0, toHash, offset, bKey.length);
				offset += bKey.length;
				System.arraycopy(pwdBytes, 0, toHash, offset, pwdBytes.length);
				md.update(toHash);
				byte[] secondHash = md.digest();

				if( ! MessageDigest.isEqual(secondHash, hashPlainData) )
					//return;
					;

				finishDHKey(bKey);

			} catch (Exception e){
				e.printStackTrace();
			}

		}

		private void finishDHKey( byte[] bKey ){
			KeyFactory kf = null;
			try {
				kf = KeyFactory.getInstance("DH");
				X509EncodedKeySpec x509Spec = new X509EncodedKeySpec( bKey );
				PublicKey clientPublicKey = kf.generatePublic(x509Spec);

				dfEnc = Cipher.getInstance("AES/CFB/PKCS5Padding", "BC");
				dfDec = Cipher.getInstance("AES/CFB/PKCS5Padding", "BC");


				sKeyAgree.doPhase(clientPublicKey, true);

				MessageDigest	hash = MessageDigest.getInstance("SHA1", "BC");

				// Then A generates the final agreement key
				dfKey = hash.digest(sKeyAgree.generateSecret());

				byte[] toUse = new byte[16];
				System.arraycopy(dfKey, 0, toUse, 0, 16);


				byte[] ivBytes = stringToBytes( "f5m8sj9c7lwq5tk5y7ti6ikgn" );

				SecretKeySpec key = new SecretKeySpec(toUse, "AES");
				dfDec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
				dfEnc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));


			} catch (Exception e) {
				e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
			}
		}

		private boolean processMsgType8( ){
			try {

				byte[] msg = getContent();
				byte[] auxNonce = new byte[NONCE_LENGTH];
				System.arraycopy(msg, 0, auxNonce, 0, auxNonce.length);
				if (nonces.contains(auxNonce))
					return false;
				nonceC = auxNonce;

				byte[] nonceS1 = new byte[NONCE_LENGTH];
				System.arraycopy(msg, nonceC.length, nonceS1, 0, nonceS1.length);
				nonceS[nonceS.length-1] += 1;
				if ( ! MessageDigest.isEqual(nonceS, nonceS1) )
					return false;

				byte[] temp = new byte[msg.length - 2*NONCE_LENGTH];
				System.arraycopy(msg, 2*NONCE_LENGTH, temp, 0, temp.length);
				byte[] plainData = dfDec.doFinal(temp); //plainData - hash dos nonces


				byte[] toHash = new byte[nonceC.length + nonceS1.length];
				System.arraycopy(nonceC, 0, toHash, 0, nonceC.length);
				System.arraycopy(nonceS1, 0, toHash, nonceC.length, nonceS1.length);
				md.update(toHash);
				byte[] hash = md.digest();


				if ( ! MessageDigest.isEqual(hash, plainData) ){
					return false;

				}

			}catch (Exception e){e.printStackTrace(); }
			return true;

		}

		private byte[] addHeader(byte[] msg, int protVersion, int contType, int length){
			msg[0] = (byte)protVersion;
			msg[1] = (byte)contType;
			msg[2] = (byte) ( length-4 >>> 8) ;
			msg[3] = (byte) (length-4) ;
			return msg;
		}

		private void sendMsgType9( ){
			try {


				byte[] msg = new byte[65536];
				int msgLength = 4;

				String sessionCS = "AES/CFB/PKCS5Padding" + ";" + "HMacSHA1";
				byte[] sessionCSBytes = sessionCS.getBytes();
				msg[msgLength++] = (byte) ( (sessionCSBytes.length) >>> 8) ;
				msg[msgLength++] = (byte) (sessionCSBytes.length ) ;

				byte[] streamKey = cipherSuiteWithKeys;

				System.out.println("STREAM KEY BYTES ");
				for (byte b: streamKey)
					System.out.print(b + " ");
				System.out.println("---------------------");


				byte[] cipheredStreamKey = dfEnc.doFinal(streamKey);

				msg[msgLength++] = (byte) ( (cipheredStreamKey.length) >>> 8) ;
				msg[msgLength++] = (byte) (cipheredStreamKey.length ) ;

				System.arraycopy(sessionCSBytes, 0, msg, msgLength, sessionCSBytes.length);
				msgLength += sessionCSBytes.length;
				System.arraycopy(cipheredStreamKey, 0, msg, msgLength, cipheredStreamKey.length);
				msgLength += cipheredStreamKey.length;

				//add nonces
				nonceC[nonceC.length-1] += 1;	//incrementar nonce
				nonceS = new byte[NONCE_LENGTH];
				srNonces.nextBytes(nonceS);
				System.arraycopy(nonceC, 0, msg, msgLength, nonceC.length);
				msgLength += nonceC.length;
				System.arraycopy(nonceS, 0, msg, msgLength, nonceS.length);
				msgLength += nonceS.length;

				//generate Hash
				byte[] toHash;
				toHash = new byte[cipheredStreamKey.length + NONCE_LENGTH*2 + sessionCSBytes.length];
				int hashOffset = 0;
				System.arraycopy(sessionCSBytes, 0, toHash, hashOffset, sessionCSBytes.length);
				hashOffset += sessionCSBytes.length;
				System.arraycopy(nonceC, 0, toHash, hashOffset, nonceC.length);
				hashOffset += nonceC.length;
				System.arraycopy(nonceS, 0, toHash, hashOffset, nonceS.length);
				hashOffset += nonceS.length;
				System.arraycopy(streamKey, 0, toHash, hashOffset, streamKey.length);
				md.update(toHash);
				byte[] hash = md.digest();

				//add Hash to msg
				System.arraycopy(hash, 0, msg, msgLength, hash.length);
				msgLength += hash.length;

				msg = addHeader(msg, PROT_VERSION, 9, msgLength);
				DatagramPacket p = new DatagramPacket(msg, 0, msgLength);
				p.setSocketAddress(socketAddress);

				try {
					dgsocket.send( p );
				} catch (IOException e) {
					e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
				}
			}catch (Exception e){e.printStackTrace(); }
		}


		@Override
		public void run() {

			byte[] buffer = new byte[65536];
			DatagramPacket dgPacket = new DatagramPacket(buffer, buffer.length);


			if( rData[1] == 6 ){
				processMsgType6(  );
				try {
					sendMsgType7();
				} catch (Exception e) {
					e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
				}

//				processMsgType6();
			}
			else
				return;

			//até receber o pacote correcto; minimiza problemas de algum atacante que tente
			//bloquear a autenticacao de alguem
			while (rData[1] != 8) {
				try {
					dgsocket.receive(dgPacket);
					rData = dgPacket.getData();

				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			if ( rData[1] == 8 ){
				if( processMsgType8() )
					sendMsgType9();

			}


//			//type 1
//			if( rData[1] == 1 ) {
//
////				clientID = getClientID();
////
////				int rlength = ((rData[2] << 8) | rData[3]);
////			 	nonceC = new byte[8];
////				System.arraycopy(rData, rlength-4, nonceC, 0, 8);
////
////				String clientPassword = users.get(clientID);
////				if(clientPassword == null)
////					System.exit(0);
////
////				try {
////					initCipherSuite(clientID, clientPassword);
////				} catch (Exception e1) {
////					e1.printStackTrace();
////					System.exit(0);
////				}
//
////				sendMsgType2(clientPassword, nonceC );
//
//
//				//receive type 3
//				try {
//					dgsocket.receive(dgPacket);
//					rData = dgPacket.getData();
//
//				} catch (IOException e) {
//					e.printStackTrace();
//				}
//
//				if(rData[1] == 3){
//					if( processType3() )
//						try {
//							sendMsgType4();
//						} catch (IllegalBlockSizeException e) {
//							e.printStackTrace();
//						} catch (BadPaddingException e) {
//							e.printStackTrace();
//						}
//
//				}
//			}


		}


//        private void initCipherSuite(String clientID, String clientPassword) throws
//                NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
//                InvalidKeySpecException, InvalidKeyException{
//
//            char[] password = clientPassword.toCharArray();
////	        byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };
////	        int iterationCount = 2048;
//
//            // Misturar ja o salt e o iterador a usar na geracap da chave
//            PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, iterationCount);
//            SecretKeyFactory keyFact = SecretKeyFactory.getInstance( authAlgorithm );
//
//        }


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
				keyGen = KeyPairGenerator.getInstance("DH", "BC");

				SecureRandom sr = new SecureRandom();

//				keyGen.initialize(dhParams, UtilsDH.createFixedRandom());
				keyGen.initialize(dhParams, sr);

				sKeyAgree = KeyAgreement.getInstance("DH", "BC");
				sPair = keyGen.generateKeyPair();

				sKeyAgree.init(sPair.getPrivate());



			} catch (Exception e) {
				e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
			}


		}



	}

	public static void main(String[] args) {

		AuthServer2 as;
		try{

			as = new AuthServer2();

			try {
				as.waitingRequests();
			} catch (IOException e) {
				e.printStackTrace();

			}
		}
		catch(Exception e){
			System.out.println("Error reading users authentication file.");
			System.exit(0);
		}
	}
}

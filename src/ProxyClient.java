
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;


//import javax.crypto.BadPaddingException;
import javax.crypto.*;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
//import javax.xml.crypto.dsig.spec.HMACParameterSpec;

import java.security.cert.Certificate;
import java.util.concurrent.TimeoutException;

class ProxyClient {

    private static final String AUTH_SERVER = "224.1.1.0";
    private static final int AUTH_SERVER_PORT = 9000;

    private static final byte PROT_VERSION = 0x1;
    private static final int NONCE_LENGTH = 8;

    private Mac hMac;
    private Key hMacKey;
    private Cipher cipher;
    private SecretKeySpec key;
    private IvParameterSpec ivSpec;
    private MulticastSocket rs;
    private DatagramSocket socket;
    private InetAddress dest;
    private int destPort;
    private SSLSocket sslsocket;

    private byte[] dfKey;


    MessageDigest md;
    Set<byte[]> noncesControl;


    private ProxyClient(String user, String password) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException, IOException,
            InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, Exception {

        createSSLSocket();

        noncesControl = new HashSet<byte[]>();
        md = MessageDigest.getInstance("SHA-1");

        dfEnc = Cipher.getInstance("AES/CFB/PKCS5Padding", "BC");
        dfDec = Cipher.getInstance("AES/CFB/PKCS5Padding", "BC");

        socket = new DatagramSocket();

        initAuthCipher();

        authenticate(user, password);

        InetAddress group;
        group = InetAddress.getByName("224.1.1.1");
        if (!group.isMulticastAddress()) {
            System.err.println("Multicast address required...");
            System.exit(0);
        }
        rs = new MulticastSocket(9999);
        rs.joinGroup(group);

        dest = InetAddress.getByName("localhost");

        destPort = 9998;

        // rs.leave if you want leave from the multicast group ...
        //rs.close();
    }

    private void initCipherSuite(String config, byte[] streamKey) {
        String completeCS = new String(streamKey);
        String[] elems = completeCS.split("\\+");


        String[] cs = config.split(";");
        String cipherType = cs[0].split("/")[0];
        String cipherName = cs[0];
        String hmacType = cs[1];
        byte[] keyBytes = stringToBytes(elems[2]);//"1n046wfzbekh0aoqvy8nrlctxifed10as9yxav" );
        byte[] ivBytes = stringToBytes(elems[3]); //"f5m8sj9c7lwq5tk5y7ti6ikgn" );
        byte[] hmacBytes = stringToBytes(elems[4]); //"6dpab5i0jo2ixz3lcb4sht3i073uf8qmn7yv6yma264gzq8wtb" );
        String provider = "BC";

        try {
            key = new SecretKeySpec(keyBytes, cipherType);
            ivSpec = new IvParameterSpec(ivBytes);
            hMacKey = new SecretKeySpec(hmacBytes, hmacType);

            cipher = Cipher.getInstance(cipherName, provider);
            hMac = Mac.getInstance(hmacType, provider);


        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            hMac.init(hMacKey);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }


    public static byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }

    /**
     * Verify data integrity and returns hash length, if integrity is secured.
     * If not, returns -1.
     */
    private int verifyHash(byte[] plainData) {
        int mLength = plainData.length - hMac.getMacLength();

        hMac.update(plainData, 0, mLength);

        //obter o hash original, antes da cifra
        byte[] mHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainData, mLength, mHash, 0, mHash.length);

        boolean integrity = MessageDigest.isEqual(hMac.doFinal(), mHash);

        if (!integrity) {
            System.err.println("INTEGRIDADA COMPROMETIDA");
            return -1;
        }

        return mHash.length;
    }

    /**
     * Deciphers and returns the plain data. Removes the first 4 bytes from the buffer.
     * This bytes were headers and weren't ciphered.
     */
    private byte[] decipher(byte[] buffer) {
        //		int cipheredMsgLength = ((buffer[2] << 8) | buffer[3]) &0xffff;
        byte[] aux = {buffer[2], buffer[3]};
        int cipheredMsgLength = new BigInteger(1, aux).intValue();

        try {
            return cipher.doFinal(buffer, 4, cipheredMsgLength);

        } catch (Exception e) {
            // e.printStackTrace();
        }

        return null;
    }

    public void run() {

        //		authenticate();

        byte[] buffer = new byte[65536];
        byte[] plainData;
        int hashLength;

        DatagramPacket p = new DatagramPacket(buffer, buffer.length);

        while (true) {

            try {
                rs.receive(p);
            } catch (IOException e) {
                // e.printStackTrace();
            }


            plainData = decipher(p.getData());


            //if integrity is not secured, we don't want this packet
            hashLength = verifyHash(plainData);
            if (hashLength == -1)
                continue;

            p.setData(plainData, 4, plainData.length - hashLength - 4);

            p.setPort(destPort);
            p.setAddress(dest);

            try {
                socket.send(p);
            } catch (IOException e) {
                // e.printStackTrace();
            }
            p.setData(buffer, 0, buffer.length);
        }
    }


    //certificado
    //TODO gerar certificados para o cliente e servidor

    private static final String KEYSTORE_PROVIDER = "JKS";
    private static final String KEY_MANAGER_FACTORY_PROVIDER = "SunX509";
    private static final String SSL_CONTEXT_PROVIDER = "TLS";
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    private static final String CLIENT_CERTIFICATE_PASSWORD = "password";
    private static final String CLIENT_CERTIFICATE_FILENAME = "clientCert";  //TODO alterar estes nomes
    private static final String SERVER_CERTIFICATE_PASSWORD = "password";
    private static final String SERVER_CERTIFICATE_FILENAME = "authServerCert"; //TODO alterar estes nomes

    private KeyManagerFactory clientKM = null;
    private TrustManagerFactory serverTrustManager = null;

	
    FileInputStream input = null;
    private KeyStore ks = null;

    //usa as chaves do cliente e servidor para criar um canal seguro
    private void createSSLSocket() {

        try {
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            input = new FileInputStream(CLIENT_CERTIFICATE_FILENAME);
            ks.load(input, CLIENT_CERTIFICATE_PASSWORD.toCharArray());
            clientKM = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY_PROVIDER);
            clientKM.init(ks, CLIENT_CERTIFICATE_PASSWORD.toCharArray());

            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            input = new FileInputStream(SERVER_CERTIFICATE_FILENAME);
            ks.load(input, SERVER_CERTIFICATE_PASSWORD.toCharArray());
            serverTrustManager = TrustManagerFactory.getInstance(KEY_MANAGER_FACTORY_PROVIDER);
            serverTrustManager.init(ks);

            SSLContext ssl = SSLContext.getInstance(SSL_CONTEXT_PROVIDER);
            ssl.init(clientKM.getKeyManagers(), serverTrustManager.getTrustManagers(),
                    SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM));
            sslsocket = (SSLSocket) ssl.getSocketFactory().createSocket("localhost", 8889);
            sslsocket.startHandshake();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private String[] readAuthAlgorithm(String filename) {
        File f = new File(filename);
        try {
            Scanner in = new Scanner(f);
            String s[] = new String[3];

            s[0] = in.next();
            in.nextLine();
            s[1] = in.next();
            in.nextLine();
            s[2] = in.next();
            in.nextLine();

            in.close();

            return s;

        } catch (FileNotFoundException e) {
            System.err.println("authConfig file not found");
//			// e.printStackTrace();
            System.exit(0);
        }
        return (new String[3]);
    }


    //TODO
    byte[] nonceC;
    byte[] nonceS;
    InetAddress authsocket;
    KeyAgreement sKeyAgree;
    KeyPair sPair;
    KeyPairGenerator keyGen;
    // Parametro para o gerador do Grupo de Cobertura de P
    private BigInteger g512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7" + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
                    + "410b7a0f12ca1cb9a428cc", 16);

    // Um grande numero primo P
    private BigInteger p512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387" + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
                    + "f0573bf047a3aca98cdf3b", 16);
    private DHParameterSpec dhParams = new DHParameterSpec(p512, g512);

    SecureRandom srNonces;

    private void initAuthCipher() throws Exception {

        srNonces = SecureRandom.getInstance("SHA1PRNG");

        authsocket = InetAddress.getByName(AUTH_SERVER);

        keyGen = KeyPairGenerator.getInstance("DH", "BC");

        SecureRandom sr = new SecureRandom();

//				keyGen.initialize(dhParams, UtilsDH.createFixedRandom());
        keyGen.initialize(dhParams, sr);

        sKeyAgree = KeyAgreement.getInstance("DH", "BC");
        sPair = keyGen.generateKeyPair();


        sKeyAgree.init(sPair.getPrivate());
    }

    private byte[] addHeader(byte[] msg, int protVersion, int contType) {
        msg[0] = (byte) protVersion;
        msg[1] = (byte) contType;
        msg[2] = (byte) ((msg.length - 4) >>> 8);
        msg[3] = (byte) (msg.length - 4);
        return msg;
    }

    private byte[] addHeader(byte[] msg, int protVersion, int contType, int length) {
        msg[0] = (byte) protVersion;
        msg[1] = (byte) contType;
        msg[2] = (byte) (length - 4 >>> 8);
        msg[3] = (byte) (length - 4);
        return msg;
    }

    private void sendMsgType6(String username) {
        try {
            byte[] key = sPair.getPublic().getEncoded();

            byte[] msg = new byte[65536];
            msg = addHeader(msg, PROT_VERSION, 6);
            int offset = 4;
            msg[offset++] = (byte) ((key.length) >>> 8);
            msg[offset++] = (byte) (key.length);

            //username hash
            byte[] usernameBytes = username.getBytes();
            md.update(usernameBytes);
            byte[] usernameHash = md.digest();
            msg[offset++] = (byte) ((usernameHash.length) >>> 8);
            msg[offset++] = (byte) (usernameHash.length);


            //nonce
            nonceC = new byte[NONCE_LENGTH];
            srNonces.nextBytes(nonceC);

            //first cipher
            byte[] toCipher_PubServer = new byte[NONCE_LENGTH + usernameBytes.length];
            System.arraycopy(nonceC, 0, toCipher_PubServer, 0, NONCE_LENGTH);
            System.arraycopy(usernameBytes, 0, toCipher_PubServer, NONCE_LENGTH, usernameBytes.length);
            byte[] ciphered_pubServer = serverAsymCipher.doFinal(toCipher_PubServer);
            msg[offset++] = (byte) ((ciphered_pubServer.length) >>> 8);
            msg[offset++] = (byte) (ciphered_pubServer.length);


            //second cipher
            byte[] toCipher_PrivUser = new byte[NONCE_LENGTH + usernameBytes.length];
            byte[] ciphered_privUser = clientAsymCipher.doFinal(toCipher_PrivUser);
            msg[offset++] = (byte) ((ciphered_privUser.length) >>> 8);
            msg[offset++] = (byte) (ciphered_privUser.length);

            //copy data to msg
            System.arraycopy(key, 0, msg, offset, key.length);
            offset += key.length;
            System.arraycopy(usernameHash, 0, msg, offset, usernameHash.length);
            offset += usernameHash.length;
            System.arraycopy(ciphered_pubServer, 0, msg, offset, ciphered_pubServer.length);
            offset += ciphered_pubServer.length;
            System.arraycopy(ciphered_privUser, 0, msg, offset, ciphered_privUser.length);
            offset += ciphered_privUser.length;


            DatagramPacket p = new DatagramPacket(msg, 0, offset);
            p.setAddress(authsocket);
            p.setPort(AUTH_SERVER_PORT);


            socket.send(p);
        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

    }

    private byte[] getContent(byte[] msg) {
        byte[] aux = {msg[2], msg[3]};
        int contentLength = new BigInteger(1, aux).intValue();
        byte[] content = new byte[contentLength];
        System.arraycopy(msg, 4, content, 0, contentLength);
        return content;
    }

    private void finishDHKey(byte[] bKey) {
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(bKey);
            PublicKey clientPublicKey = kf.generatePublic(x509Spec);

            sKeyAgree.doPhase(clientPublicKey, true);

            MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");

            // Then A generates the final agreement key
            dfKey = hash.digest(sKeyAgree.generateSecret());
            byte[] ivBytes = stringToBytes("f5m8sj9c7lwq5tk5y7ti6ikgn");

            byte[] toUse = new byte[16];
            System.arraycopy(dfKey, 0, toUse, 0, 16);

            SecretKeySpec key = new SecretKeySpec(toUse, "AES");
            dfDec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            dfEnc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

//			System.out.println("dfKey = " + new String(dfKey));
//			System.out.println("++++++------------+++++++");
//			for(byte b: dfKey)
//				System.out.print(b + " ");
//			System.out.println("++++++-----------------+++++++");


        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }


    private boolean processMsgType7(byte[] packet) {
        try {
            byte[] msg = getContent(packet);
            int length = msg.length;
            byte[] aux = {msg[0], msg[1]};
            int keyLength = new BigInteger(1, aux).intValue();

//			System.out.println("MSG");
//			for (byte b: msg)
//				System.out.print(b + " ");
//			System.out.println("----");


            int offset = 2;
            byte[] auxNonce = new byte[NONCE_LENGTH];
            System.arraycopy(msg, offset, auxNonce, 0, NONCE_LENGTH);
            offset += auxNonce.length;
            if (noncesControl.contains(auxNonce)) {
                return false;
            }
            nonceC[nonceC.length - 1] += 1;


            if (!MessageDigest.isEqual(auxNonce, nonceC)) {
                nonceC[nonceC.length - 1] -= 1;
                return false;
            }


            nonceS = new byte[NONCE_LENGTH];
            System.arraycopy(msg, offset, nonceS, 0, NONCE_LENGTH);
            offset += NONCE_LENGTH;

            byte[] key = new byte[keyLength];
            System.arraycopy(msg, offset, key, 0, keyLength);
            offset += keyLength;

            //calc auxHash
            md.update(msg, 2, offset);
            byte[] auxHash = md.digest();

            byte[] toDecipher = new byte[length - offset];
            System.arraycopy(msg, offset, toDecipher, 0, toDecipher.length);
            byte[] plainData = serverAsymCipher.doFinal(toDecipher);

            if (!MessageDigest.isEqual(auxHash, plainData))
//			return false;
                ;


            finishDHKey(key);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }


    private void sendMsgType8(InetAddress adddres, int port) {
        try {
            byte[] msg = new byte[65536];
            int msgLength = 4;

            //generate new Nonce
            srNonces.nextBytes(nonceC);
            System.arraycopy(nonceC, 0, msg, msgLength, nonceC.length);
            msgLength += nonceC.length;


            nonceS[nonceS.length - 1] += 1;
            System.arraycopy(nonceS, 0, msg, msgLength, nonceS.length);
            msgLength += nonceS.length;

            md.update(msg, 4, NONCE_LENGTH * 2);
            byte[] hash = md.digest();

            byte[] cipheredHash = dfEnc.doFinal(hash);
            System.arraycopy(cipheredHash, 0, msg, msgLength, cipheredHash.length);
            msgLength += cipheredHash.length;


            msg = addHeader(msg, PROT_VERSION, 8, msgLength);
            DatagramPacket dp = new DatagramPacket(msg, 0, msgLength);
            dp.setAddress(adddres);
            dp.setPort(port);

            try {
                socket.send(dp);
            } catch (IOException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean processMsgType9(byte[] packet) {
        try {


            byte[] msg = getContent(packet);
            int length = msg.length;

            byte[] aux = {msg[0], msg[1]};
            int sessionCPsize = new BigInteger(1, aux).intValue();
            byte[] aux2 = {msg[2], msg[3]};
            int cipheredKeySize = new BigInteger(1, aux2).intValue();

            int initOffset = 4;
            int offset = initOffset;


            String sessionCP = new String(msg, offset, sessionCPsize);
            offset += sessionCPsize;


            byte[] cipheredStreamKey = new byte[cipheredKeySize];
            System.arraycopy(msg, offset, cipheredStreamKey, 0, cipheredKeySize);
            offset += cipheredKeySize;
            byte[] streamKey = dfDec.doFinal(cipheredStreamKey);
//			byte[]	streamKey = cipheredStreamKey;


            nonceC[nonceC.length - 1] += 1;
            byte[] auxNonce = new byte[NONCE_LENGTH];
            System.arraycopy(msg, offset, auxNonce, 0, NONCE_LENGTH);
            if (!MessageDigest.isEqual(nonceC, auxNonce)) {
                nonceC[nonceC.length - 1] -= 1;
                return false;
            }
            offset += NONCE_LENGTH;

            System.arraycopy(msg, offset, auxNonce, 0, NONCE_LENGTH);
            if (noncesControl.contains(auxNonce)) {
                nonceC[nonceC.length - 1] -= 1;
                return false;
            }
            offset += NONCE_LENGTH;

            byte[] msgHash = new byte[length - offset];
            System.arraycopy(msg, offset, msgHash, 0, length - offset);


            //generate Hash
            byte[] toHash = new byte[sessionCPsize + 2 * NONCE_LENGTH + streamKey.length];
            int hashOffset = 0;
            System.arraycopy(msg, initOffset, toHash, hashOffset, sessionCPsize);
            hashOffset += sessionCPsize;
            System.arraycopy(nonceC, 0, toHash, hashOffset, NONCE_LENGTH);
            hashOffset += NONCE_LENGTH;
            System.arraycopy(auxNonce, 0, toHash, hashOffset, NONCE_LENGTH);
            hashOffset += NONCE_LENGTH;
            System.arraycopy(streamKey, 0, toHash, hashOffset, streamKey.length);
            hashOffset += streamKey.length;
            md.update(toHash);
            byte[] hash = md.digest();
            if (!MessageDigest.isEqual(hash, msgHash)) {
                //nonceC[nonceC.length-1] -= 1;
                //return false;
            }

            initCipherSuite(sessionCP, streamKey);


            noncesControl.add(auxNonce);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }

    private void authenticate(String username, String password) throws Exception {

        initAuthCipher();

        byte[] buffer = new byte[65536];
        DatagramPacket dgPacket = new DatagramPacket(buffer, buffer.length);

        socket.setSoTimeout(7000);
        do {
            try {
                sendMsgType6(username);

                socket.receive(dgPacket);

                processMsgType7(dgPacket.getData());

                InetAddress address = dgPacket.getAddress();
                int port = dgPacket.getPort();

                sendMsgType8(address, port);

                socket.receive(dgPacket);

                break;
            } catch (SocketTimeoutException te) {
                continue;
            }
        } while (true);

        processMsgType9(dgPacket.getData());


//		if (processMsgType7())


    }


    static public void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Use: ProxyClient user password");

        }


        System.out.println("Authenticating...");
        ProxyClient pc = new ProxyClient(args[0], args[1]);
        System.out.println("Authenticated");
        System.out.println("Starting stream ...");
        pc.run();
    }
}
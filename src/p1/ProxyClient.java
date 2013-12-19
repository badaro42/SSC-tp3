package p1;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

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


    MessageDigest md;
//    Set<byte[]> noncesControl;


    private ProxyClient(String user, String password) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException, IOException,
            InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, Exception {

        createSSLSocket();

//        noncesControl = new HashSet<byte[]>();
        md = MessageDigest.getInstance("SHA-1");

        socket = new DatagramSocket();

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




//    public static byte[] stringToBytes(String s) {
//        byte[] b2 = new BigInteger(s, 36).toByteArray();
//        return Arrays.copyOfRange(b2, 1, b2.length);
//    }

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

    private static final String CLIENT_TRUST_STORE = "clienttruststore";
//    private static final String CLIENT_KEYSTORE_NAME = "clientks";
    private static final String GENERAL_PASSWORD = "password";
//    private static final String CLIENT_CERTIFICATE_FILENAME = "clientCert";  //TODO alterar estes nomes
//    private static final String SERVER_CERTIFICATE_PASSWORD = "password";
//    private static final String SERVER_CERTIFICATE_FILENAME = "authServerCert"; //TODO alterar estes nomes

    private KeyManagerFactory clientKM = null;
    private TrustManagerFactory serverTrustManager = null;

    FileInputStream input = null;
    private KeyStore ks = null;

    //usa as chaves do cliente e servidor para criar um canal seguro
    private void createSSLSocket() {

        try {
//            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
//            input = new FileInputStream(CLIENT_KEYSTORE_NAME);
//            ks.load(input, GENERAL_PASSWORD.toCharArray());
//            clientKM = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY_PROVIDER);
//            clientKM.init(ks, GENERAL_PASSWORD.toCharArray());

            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            input = new FileInputStream(CLIENT_TRUST_STORE);
            ks.load(input, GENERAL_PASSWORD.toCharArray());
            serverTrustManager = TrustManagerFactory.getInstance(KEY_MANAGER_FACTORY_PROVIDER);
            serverTrustManager.init(ks);

            SSLContext ssl = SSLContext.getInstance(SSL_CONTEXT_PROVIDER);
            ssl.init(null, serverTrustManager.getTrustManagers(),
                    SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM));
            sslsocket = (SSLSocket) ssl.getSocketFactory().createSocket(AUTH_SERVER, AUTH_SERVER_PORT);
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

    private byte[] getContent(byte[] msg) {
        byte[] aux = {msg[2], msg[3]};
        int contentLength = new BigInteger(1, aux).intValue();
        byte[] content = new byte[contentLength];
        System.arraycopy(msg, 4, content, 0, contentLength);
        return content;
    }

    //TODO
    private void authenticate(String username, String password) throws Exception {

        PrintWriter out;
        BufferedReader in;

        try {
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslsocket.getOutputStream())));
            in = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));

            out.println(username);
            out.println(password);

            String ciphersuite = in.readLine();



        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initCipherSuite(String config) {

        String[] elems = config.split("\\+");

        String cipherType = elems[0];
        String hmacType = elems[1];
        byte[] keyBytes = elems[2].getBytes();//"1n046wfzbekh0aoqvy8nrlctxifed10as9yxav" );
        byte[] ivBytes = elems[3].getBytes(); //"f5m8sj9c7lwq5tk5y7ti6ikgn" );
        byte[] hmacBytes = elems[4].getBytes(); //"6dpab5i0jo2ixz3lcb4sht3i073uf8qmn7yv6yma264gzq8wtb" );
        String provider = "BC";

        try {
            key = new SecretKeySpec(keyBytes, cipherType);
            ivSpec = new IvParameterSpec(ivBytes);
            hMacKey = new SecretKeySpec(hmacBytes, hmacType);

            cipher = Cipher.getInstance(cipherType, provider);
            hMac = Mac.getInstance(hmacType, provider);

            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            hMac.init(hMacKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    static public void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Use: p1.ProxyClient user password");
        }

        System.out.println("Authenticating...");
        ProxyClient pc = new ProxyClient(args[0], args[1]);
        System.out.println("Authenticated");
        System.out.println("Starting stream ...");
        pc.run();
    }
}
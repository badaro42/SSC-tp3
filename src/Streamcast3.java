import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.Key;
import java.util.Arrays;

class Streamcast3 {

	protected static short sessionID;
	private static short PROT_VERSION = 3;
	private static short STREAM_PACKET_TYPE = 5;

	private static final String CONFIG_NETWORK_FILENAME = "configNetwork";
	private static final String CONFIG_CIPHER_SUITE_FILENAME = "configCS";
	private static final String DEFAULT_ADDRESS = "224.1.1.1";
	private static final int DEFAULT_PORT = 9999;

	private static String address;
	private static int port;

	private static Cipher cipher;
	private static Mac hMac;


	private static void readConfigNetworkFile(String filename){
		try{
			FileReader fr = new FileReader(filename);
			BufferedReader br = new BufferedReader(fr);

			String line = br.readLine();
			String[] add_port = line.split(" ");
			address = add_port[0];
			port = Integer.parseInt(add_port[1]);

			br.close();
		} catch (Exception e){
			e.printStackTrace();
		}
		address = DEFAULT_ADDRESS;
		port = DEFAULT_PORT;
	}

	private static String[] getConfig(String filename) throws IOException{
		FileReader fr = new FileReader(filename);
		BufferedReader br = new BufferedReader(fr);

		String[] config = new String[7];

		for(int i = 0; i < 7; i++)
			config[i] = br.readLine().split(" ")[0];

		br.close();
		return config;
	}

	public static byte[] stringToBytes(String s) {
		byte[] b2 = new BigInteger(s, 36).toByteArray();
		return Arrays.copyOfRange(b2, 1, b2.length);
	}


	private static void initCipherSuite(String filename){
		FileReader fr = null;
		try {
			fr = new FileReader(filename);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.out.println("Config CS file not found");
			System.exit(0);
		}
		BufferedReader br = new BufferedReader(fr);

		try{
			String alg = "";
			String algMode = "";
			boolean padding = false;
			String hmac = "";
			String key = "";
			String hmacKey = "";
			String ivKey = "";
			try {
				alg = br.readLine().trim();
				algMode = br.readLine();
				padding = ! algMode.split("/")[2].equals("NoPadding");
				hmac = br.readLine().split(" ")[0];
				key = br.readLine().split(" ")[0];
				hmacKey = br.readLine().split(" ")[0];
				if (padding)
					ivKey = br.readLine().split(" ")[0];

			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("Error reading config CS file");
				System.exit(0);
			}


			byte[] keyBytes = stringToBytes(key);
			byte[] hmacBytes = stringToBytes(hmacKey);
			byte[] ivBytes = stringToBytes(ivKey);

			SecretKeySpec keyspec = new SecretKeySpec(keyBytes, algMode);

			cipher = Cipher.getInstance(alg, "BC");
			hMac = Mac.getInstance(hmac, "BC");
			Key hMacKey = new SecretKeySpec(hmacBytes, hmac);
			IvParameterSpec ivSpec = null;
			if (padding){
				ivSpec = new IvParameterSpec(ivBytes);
				cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivSpec);
			}
			else
				cipher.init(Cipher.ENCRYPT_MODE, keyspec);

			hMac.init(hMacKey);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}

	}

	static public void main( String []args ) throws Exception {
		// Use: args[0] the stream. file

		readConfigNetworkFile(CONFIG_NETWORK_FILENAME);
		initCipherSuite(CONFIG_CIPHER_SUITE_FILENAME);


		sessionID = 8131;	//TODO random

		int size;
		int blockcount = 0;
		long marktime;
		DataInputStream dstream = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buffer = new byte[65000];

		// To send the stream, it is only necessary to have a Datagram socket
		// You must remember that because we will not receive nothing in
		// multicast, a datagram socket is ok.

		DatagramSocket dgsocket = new DatagramSocket();
		InetSocketAddress epaddr = new InetSocketAddress( address, port);
		DatagramPacket dgpacket = new DatagramPacket(buffer, buffer.length, epaddr );

		long time0 = System.nanoTime(); // Iinitial ref time
		long qmark0 = 0;
		byte seq = 0;

		while ( dstream.available() > 0 )
		{
			size = dstream.readShort();
			marktime = dstream.readLong();
			if ( blockcount == 0 ) qmark0 = marktime; // stream format ref. time
			blockcount += 1;

			buffer[0] = seq;	//nr. seq
			seq = (byte)((seq + 1)%512);
			int sessionID = 0xf5a; // 3 bytes
			buffer[1] = (byte) ( (sessionID >>> 16) & 0xf );
			buffer[2] = (byte) ( (sessionID >>> 8) & 0xf );
			buffer[3] = (byte) ( sessionID & 0xf );
			dstream.readFully(buffer, 4, size );


//			Cipher ------------

			byte[] cipherData = new byte[cipher.getOutputSize(size + hMac.getMacLength() + 4)];
			int ctLength = cipher.update(buffer, 0, size+4, cipherData, 0);
			hMac.update(buffer, 0, size+4);
			ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherData, ctLength);

//			-----------------
//	        add Headers 

			byte[] packet = new byte[ 4 + ctLength ];
			packet[0] = (byte) PROT_VERSION;
			packet[1] = (byte) STREAM_PACKET_TYPE;
			packet[2] = (byte) ( ctLength >>> 8 );
			packet[3] = (byte) ctLength;

			System.arraycopy(cipherData, 0, packet, 4, cipherData.length);

//	        -----------------------

			dgpacket.setData(packet, 0, ctLength + 4 );
			dgpacket.setSocketAddress( epaddr );

			long time1 = System.nanoTime(); //time in this moment
			Thread.sleep(Math.max(0,((marktime-qmark0)-(time1-time0))/1000000));

			dgsocket.send( dgpacket );
			System.out.print( "." );


		}

		dstream.close();
		dgsocket.close();

		System.out.println("All stream blocks sent, Nr of blocks: " + blockcount);
	}
}
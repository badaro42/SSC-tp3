
import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.Key;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Streamcast3 {

	protected static short sessionID;
	private static short PROT_VERSION = 1;
	private static short STREAM_PACKET_TYPE = 5;
	private static String ADDRESS= "224.1.1.1";
	private static int PORT = 9999;
	private static final String CONFIG_CS_FILENAME = "configCS";
	private static final String CONFIG_NETWORKING_FILENAME = "configNetwork";



	private static String[] getConfig(String filename) throws IOException{
		FileReader fr = new FileReader(filename);
		BufferedReader br = new BufferedReader(fr);

		String[] config = new String[7];

		for(int i = 0; i < 6; i++)
			config[i] = br.readLine().split(" ")[0];

		br.close();
		return config;
	}
	private static void readNetworkingConfig(String filename){
		File f = new File(filename);
		try{
			Scanner in = new Scanner(f);
			ADDRESS = in.next();
			PORT = Integer.parseInt(in.next());
		} catch (Exception e){ }
	}

	static public void main( String []args ) throws Exception {
		// Use: args[0] the stream. file
		// args[1] to give the multicast group address
		// args[2[ to give the used port

		sessionID = 8131;

		readNetworkingConfig(CONFIG_NETWORKING_FILENAME);
		String[] confs = getConfig(CONFIG_CS_FILENAME);
		String cipherType = confs[0];
		String cipherMode = confs[1];
		String provider = "BC";
		String hmacType = confs[2];

//		cipherName = "AES/CFB/PKCS5Padding";
//		hmacType = "HMacSHA1";
		boolean padding = ! cipherMode.split("/")[2].equals("NoPadding");

		byte[] keyBytes = confs[3].getBytes(); //"1n046wfzbekh0aoqvy8nrlctxifed10a".getBytes();
		byte[] hmacBytes = confs[4].getBytes(); //"6dpab5i0jo2ixz3lcb4sht3i073uf8qmn7yv6yma264gzq8wtb".getBytes();
		byte[] ivBytes = null;
		if (padding)
			ivBytes = confs[5].getBytes(); //"f5m8sj9c7lwq5tk5".getBytes();

		SecretKeySpec key = new SecretKeySpec(keyBytes, cipherType);
		Cipher cipher = Cipher.getInstance(cipherMode, provider);
		Mac hMac = Mac.getInstance(hmacType, provider);
		Key hMacKey = new SecretKeySpec(hmacBytes, hmacType);
		if (padding){
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		}
		else
			cipher.init(Cipher.ENCRYPT_MODE, key);


		int port = PORT;
		int size;
		int blockcount = 0;
		long marktime;
		DataInputStream dstream = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buffer = new byte[65000];

		// To send the stream, it is only necessary to have a Datagram socket
		// You must remember that because we will not receive nothing in
		// multicast, a datagram socket is ok.

		DatagramSocket dgsocket = new DatagramSocket();
		InetSocketAddress epaddr = new InetSocketAddress( ADDRESS, port);
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

//			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			byte[] cipherData = new byte[cipher.getOutputSize(size + hMac.getMacLength() + 4)];
			int ctLength = cipher.update(buffer, 0, size+4, cipherData, 0);
			hMac.init(hMacKey);
			hMac.update(buffer, 0, size+4);
			ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherData, ctLength);//Final(cipherData, ctLength);

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
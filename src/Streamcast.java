
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Streamcast {
	
	protected static short sessionID;
	private static short PROT_VERSION = 1;
	private static short STREAM_PACKET_TYPE = 5;
	private static String ADDRESS= "224.1.1.1";
	private static int PORT = 9999;
	
	
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
	

	static public void main( String []args ) throws Exception {
		// Use: args[0] the stream. file
		// args[1] to give the multicast group address
		// args[2[ to give the used port

		sessionID = 0b0001_1111_1100_0011;
		
		String filename = "config";
		
		String[] confs = getConfig(filename);
		String cipherType = confs[0];
		String cipherName = confs[1];
		String provider = "BC";
		String hmacType = confs[2];

		byte[] keyBytes = stringToBytes(confs[3]);
		byte[] ivBytes = stringToBytes(confs[4]);
		byte[] hmacBytes = stringToBytes(confs[5]);
		
		
		SecretKeySpec key = new SecretKeySpec(keyBytes, cipherType);
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(cipherName, provider);
        Mac hMac = Mac.getInstance(hmacType, provider);
        Key hMacKey = new SecretKeySpec(hmacBytes, hmacType);

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
			
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
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
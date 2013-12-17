
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

/**
 * Two party key agreement using Diffie-Hellman
 */
public class teste
{


	public static void main(
			String[]    args)
			throws Exception
	{

		String key = "1n046wfzbekh0avggfgdhsefsd1n046wfzbekh0avggfgdhsefs";
		byte[] k = Utils.toByteArray(key);
		System.out.println(k.length);
		for(byte b: k)
			System.out.print(b + " ");
		System.out.println();

		for(byte b: key.getBytes())
			System.out.print(b + " ");
		System.out.println();



	}
}

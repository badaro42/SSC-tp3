
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class to compile the DH - Examples for SSRC
 */
public class UtilsDH
	extends Utils
{   
    private static class FixedRand extends SecureRandom
    {
        MessageDigest	sha;
        byte[]			state;
        
        FixedRand(){
            try
            {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();

            }
            catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException("Error finding SHA-1!");
            }
        }
	
	    public void nextBytes(byte[] bytes)
	    {
	        int	off = 0;
	        
	        sha.update(state);
	        
	        while (off < bytes.length)
	        {	            
	            state = sha.digest();
	            
	            if (bytes.length - off > state.length)
	            {
	                System.arraycopy(state, 0, bytes, off, state.length);
	            }
	            else
	            {
	                System.arraycopy(state, 0, bytes, off, bytes.length - off);
	            }
	            
	            off += state.length;
	            
	            sha.update(state);
	        }
	    }
    }
    
    /**
     * Return: SecureRandom, which produces the same value.
     * <b>This is a test</b>
     * @return a fixed random
     */
    public static SecureRandom createFixedRandom()
    {
        return new FixedRand();
    }
}

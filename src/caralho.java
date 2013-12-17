/**
 * Created by Rafael on 17-12-2013.
 */
public class caralho {

    public static void main(String []args) throws Exception{
        String key = "1hbnfe51760mwgyxne1hbnfe51760mwgyxne";
        byte[] arrkey = Utils.toByteArray(key);
        System.out.println("plainkey - " + Utils.toHex(key.getBytes()));
        System.out.println("key -      " + Utils.toHex(arrkey));
        System.out.println("arrkey - " + arrkey.length);
        System.out.println("key - " + key.length());
    }

}

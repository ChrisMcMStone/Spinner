import java.security.MessageDigest;

public class Utils {

     public static String getSha256(byte[] value) {
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(value);
			return byteArrayToHexString(md.digest());
		} catch(Exception ex){
			throw new RuntimeException(ex);
		}
	 }

    /**
     * @param needle A string to look for
     * @param hayStack An array of strings
     * @return the index of the first string in hayStack ends with needle, or -1 is no such string exists.
     */
    public static int stringListMatch(String needle, String[] hayStack) {
        for (int i = 0; i < hayStack.length; i++) {
            if (needle.endsWith(hayStack[i]))  { return i; }
        }
        return -1;
    }

    public static String byteArrayToHexString(byte[] data) { 
        return  byteArrayToHexString(data, 0, data.length);
    }

    public static String byteArrayToHexString(byte[] data,int start, int stop) { 
        StringBuffer buf = new StringBuffer();
        for (int i = start; i < stop; i++) { 
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do { 
                if ((0 <= halfbyte) && (halfbyte <= 9)) 
                    buf.append((char) ('0' + halfbyte));
                else 
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = data[i] & 0x0F;
            } while(two_halfs++ < 1);
        } 
        return buf.toString();
    } 

    // Code from http://javaconversions.blogspot.co.uk
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}

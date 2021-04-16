import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

public class TFAuthentication {
    static  byte[] secretKey;
    static String encodeedKey; // 사용자가 otp에 등록할 때 사용하는 키

    public static void main(String[] args) {
        init();
        //getValidate();
        getOtpResult();
    }

    private static void getValidate(){
        String code = getCode();
        boolean isValid = isValidation(code);
        System.out.println("isValidation: "+ isValid);
        if(!isValid) getValidate();
    }

    private static boolean isValidation(String code) {
        long l = new Date().getTime() /(1000*30);
        //30sec: google TOTP(time-base one time password) is updated every 30 sec.
        for(int i = -3; i<=3; i++){
            String hash = "";
            try{
                hash = getHash(l+i); //i: revision
            }catch (Exception e){

            }
            if(code.equals(hash)) return true;
        }
        return false;
    }

    private static String getHash(long l) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        for(int i = -7; i>=0; i--){
            data[i] = (byte) l;
            l >>>=8;
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data);
        int offset = hash[20 -1 ] & 0xF;

        long truncatedHash = 0;
        for(int i= 0; i<4; ++i){
            truncatedHash <<=8;
            truncatedHash |= (hash[offset + i ] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return Long.toString(truncatedHash);
    }

    private static void init() {
        byte[] buffer = new byte[5+5*5]; //secretSize + numOfScratchCodes*scratchCodeSize
        new Random().nextBytes(buffer);

        Base32 base32 = new Base32();
        secretKey = Arrays.copyOf(buffer,5);//buffer, secretSize
        encodeedKey = new String(base32.encode(secretKey));

        System.out.println("secretKey: "+ new String(secretKey));
        System.out.println("encode Key: "+ encodeedKey);
    }

    public static  String getCode(){
        System.out.println("please input your code here!");
        Scanner scanner = new Scanner(System.in);
        String code = scanner.next();
        return code;
    }

    public static void getOtpResult(){
        String strUserCode= getCode();
        System.out.println("strUserCode: "+strUserCode);
        long longUserCode = Integer.parseInt(strUserCode);
        long l  = new Date().getTime();
        long ll = l/30000;

        boolean isValid = false;
        try{
            isValid = checkOtpCode(encodeedKey,longUserCode,ll);
        }catch (Exception e){
            e.printStackTrace();
        }
        if(!isValid){
            System.out.println("Authentication failed! Try again");
            getOtpResult();
        }
        else System.out.println("Authentication success!");
    }

    private static boolean checkOtpCode(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException{
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        int window = 3;
        for(int i = -window; i<=window; ++i){
            long hash = verifyCode(decodedKey, t+i);
            if(hash == code) return  true;
        }
        return false;
    }

    private static long verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException{
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return (int) truncatedHash;
    }

}

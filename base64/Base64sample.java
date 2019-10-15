import java.net.URL;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

class Base64sample {
    public static void main(String args[]){
        try{
            URL myurl = new URL("http://example.com");
            Base64.Encoder urec = Base64.getUrlEncoder();
            System.out.println("URL: " + myurl);
            String str = "thisIsAnExampleString";
            Base64.Encoder enc= Base64.getEncoder();
            
            //encoding  byte array into base 64
            byte[] encoded = urec.encode(myurl.toString().getBytes("UTF8"));
            byte[] strenc =enc.encode(str.getBytes("UTF-8"));
            
            System.out.println("Base64 Encoded URL : " + new String(encoded,"UTF-8"));
            System.out.println("Base64 Encoded String : " + new String(strenc,"UTF-8"));
        
            //decoding byte array into base64
            Base64.Decoder urdc= Base64.getUrlDecoder();
            Base64.Decoder dec= Base64.getDecoder();
            byte[] urdec=urdc.decode(encoded);
            byte[] strdec=dec.decode(strenc);
            
            System.out.println("Base64 Decoded URL : " + new String(urdec,"UTF-8"));
            System.out.println("Base64 Decoded String : " + new String(strdec,"UTF-8"));
        }

        catch(Exception e){
            System.out.println("Invalid URL Exception");
        }
    }
}
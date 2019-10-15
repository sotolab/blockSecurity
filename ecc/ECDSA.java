import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;
import java.security.spec.*;

public class ECDSA {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC","SunEC");
    
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("sect163k1");
        kpg.initialize(ecsp);
    
        KeyPair kp = kpg.genKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();
        System.out.println(privKey.toString());
        System.out.println(pubKey.toString());
        
        Signature ecdsa;
        ecdsa = Signature.getInstance("SHA1withECDSA","SunEC");
        ecdsa.initSign(privKey);
    
        String text = "In teaching others we teach ourselves";
        System.out.println("Text: " + text);
        byte[] baText = text.getBytes("UTF-8");
    
        ecdsa.update(baText);
        byte[] baSignature = ecdsa.sign();
        System.out.println("Signature: 0x" + (new BigInteger(1, baSignature).toString(16)).toUpperCase());
    
        Signature signature;
        signature = Signature.getInstance("SHA1withECDSA","SunEC");
        signature.initVerify(pubKey);
        signature.update(baText);
        boolean result = signature.verify(baSignature);
        System.out.println("Valid: " + result);
    }
}
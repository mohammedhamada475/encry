import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 

public class AES {
 
    public static void main(String[] args) throws Exception {
        String plainText = "Hello This Is Belal , from network security class IUG ";
 
        // public and private keys 
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        

        Map<String, Object> keys1 = keys;
        PrivateKey privateKey1 = (PrivateKey) keys1.get("private");
        PublicKey publicKey1 = (PublicKey) keys1.get("public");
 
        //  AES Key
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        String secretAESKeyString = Base64.getEncoder().encodeToString(secKey.getEncoded());

       
 
        // Encrypt with AES key 
        byte[] decodedKey = Base64.getDecoder().decode(secretAESKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
 
        // AES 
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        String encryptedText =  Base64.getEncoder().encodeToString(byteCipherText);

         
 
        // Encrypt AES Key with RSA Private Key 
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.ENCRYPT_MODE, privateKey);
      

        String encryptedAESKeyString = Base64.getEncoder().encodeToString(cipher2.doFinal(secretAESKeyString.getBytes()));
 
      
 
        // decrypt the AES Key with RSA Public key 
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        String decryptedText = new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKeyString)));

        
 
        // Now decrypt Message with decrypted AES key
        byte[] decodedKey1 = Base64.getDecoder().decode(decryptedText);
        SecretKey originalKey1 = new SecretKeySpec(decodedKey1, 0, decodedKey1.length, "AES");
 
        // AES defaults 
        Cipher aesCipher1 = Cipher.getInstance("AES");
        aesCipher1.init(Cipher.DECRYPT_MODE, originalKey1);
        byte[] bytePlainText = aesCipher1.doFinal(Base64.getDecoder().decode(encryptedText));
        String decryptedText1 = new String(bytePlainText);


         
 
        System.out.println("Original Message to encrypt:" + plainText);
        System.out.println("AES Key is:" + secretAESKeyString);
        System.out.println("Original decrypted Message:" + decryptedText1);
 
    }
 
    
  
}

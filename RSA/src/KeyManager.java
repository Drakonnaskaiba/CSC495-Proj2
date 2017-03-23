import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KeyManager{
    protected KeyPairGenerator kpg;
    protected KeyPair keyPair;
    protected PublicKey theirKey;
    protected KeyAgreement keyAgree;
    protected int KEYSIZE;
    
    public byte[] returnMyPublicKey(){
        return keyPair.getPublic().getEncoded();
        
    }
    public byte[] returnMyPrivateKey(){
        return keyPair.getPrivate().getEncoded();
    }
    public void setTheirPublicKey(byte[] theirs){
        try {
            KeyFactory kef = KeyFactory.getInstance("RSA");
            this.theirKey = kef.generatePublic(new X509EncodedKeySpec(theirs));
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        
    }
    public PublicKey returnTheirPublicKey(){
        return this.theirKey;
    }
}
class RSAKeyManager extends KeyManager{
    
    
     public RSAKeyManager(int keysize){
        super.KEYSIZE = keysize;
        super.keyPair = genRSAKey(2048);
         
    }


public KeyPair genRSAKey(int bits) {
        
        try {
            //RSAKeyGenParameterSpec kgspec = new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4);
            super.kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpg.genKeyPair();
    }

public byte[] encrypt_with_RSA(byte[] message){
    try {
            // YOUR CODE GOES HERE

            Cipher rsacipher = Cipher.getInstance("RSA");
            rsacipher.init(Cipher.ENCRYPT_MODE, super.theirKey);

            
                return rsacipher.doFinal(message);

            

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(RSAKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    
    
}

public byte[] decrypte_with_RSA(byte[] message){
    
         try {
             Cipher rsacipher = Cipher.getInstance("RSA");
             rsacipher.init(Cipher.DECRYPT_MODE, super.keyPair.getPrivate());
             
             return rsacipher.doFinal(message);
             
         } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
             Logger.getLogger(RSAKeyManager.class.getName()).log(Level.SEVERE, null, ex);
         }
         return null;
}

public byte[] gen_DES_key(){
         try {
             SecureRandom randsec = new SecureRandom();
             KeyGenerator keygen = KeyGenerator.getInstance("DES");
             
             keygen.init(randsec);
             
             SecretKey secretkey = keygen.generateKey();
             
             
             return secretkey.getEncoded();
             
             
             
         } catch (NoSuchAlgorithmException ex) {
             Logger.getLogger(RSAKeyManager.class.getName()).log(Level.SEVERE, null, ex);
         }
         return null;
}

}
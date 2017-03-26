
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
        BigInteger priKeyBI = ((DHPrivateKey) keyPair.getPrivate()).getX();
        return priKeyBI.toByteArray();
    }
    public void setTheirPublicKey(byte[] theirs){
        try {
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(theirs);
            this.theirKey = kf.generatePublic(x509Spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public PublicKey returnTheirPublicKey(){
        return this.theirKey;
    }
}
class DHKeyManager extends KeyManager {
    private DHParameterSpec dhparamSpec;
    public DHKeyManager(int keysize){
        super.KEYSIZE = keysize;
    }
    
    public void generateParameters(){
        try {
            
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(super.KEYSIZE);
            AlgorithmParameters params = paramGen.generateParameters();
            this.dhparamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
            super.kpg = KeyPairGenerator.getInstance("DiffieHellman");
            super.kpg.initialize(dhparamSpec);
            super.keyPair = super.kpg.genKeyPair();
            super.keyAgree = KeyAgreement.getInstance("DiffieHellman");
            super.keyAgree.init(keyPair.getPrivate());
            
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException ex) {
            Logger.getLogger(DHKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void setDHParameterSpec(){
        try {
            PublicKey pubKey = returnTheirPublicKey();
            this.dhparamSpec = ((DHPublicKey) pubKey).getParams();
            super.kpg = KeyPairGenerator.getInstance("DiffieHellman");
            super.kpg.initialize(this.dhparamSpec);
            super.keyPair = super.kpg.genKeyPair();
            super.keyAgree = KeyAgreement.getInstance("DiffieHellman");
            super.keyAgree.init(keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            Logger.getLogger(DHKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public byte[] computeSharedSecret(){
        try {
            super.keyAgree.doPhase(returnTheirPublicKey(), true);
        } catch (InvalidKeyException | IllegalStateException ex) {
            Logger.getLogger(DHKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return super.keyAgree.generateSecret();
    }
}

class DESEncryption {
    // private class fields
    private final String ENCRYPTION_ALGO = "DES/ECB/PKCS5Padding";
    private final int KEYSIZE = 8;
    private SecretKeySpec secretKey;
    private Cipher cipher;
    private byte[] key;
    
    
    // class constructor
    public DESEncryption(byte[] sharedkey) {
        if (sharedkey.length == KEYSIZE){
            this.key = sharedkey;
        } else {
            this.key = new byte[KEYSIZE];
        }
        this.initCipher();
    }
    
    public byte[] getKey(){
        return this.key;
    }
    
    public boolean setKey(byte[] input){
        if (input.length == KEYSIZE) {
            this.key = input;
            return true;
        }
        return false;
    }
    
    private void initCipher(){
        try {
            this.secretKey = new SecretKeySpec(this.key, 0, this.key.length, "ENCRYPTION_ALGO");
            cipher = Cipher.getInstance(ENCRYPTION_ALGO);
            System.out.println("Keysize: " + this.key.length);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public String encryptDES(String plaintext){
        String ciphertext = "";
        try {
            SecretKeyFactory sf = SecretKeyFactory.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, sf.generateSecret(secretKey));
            byte[] plainBytes = plaintext.getBytes();
            byte[] cipherBytes = cipher.doFinal(plainBytes);
            ciphertext = new String(Base64.getEncoder().encode(cipherBytes));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ciphertext;
    }
    
    public String decryptDES(String ciphertext){
        String plaintext = "";
        try { 
            SecretKeyFactory sf = SecretKeyFactory.getInstance("DES");
            byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);  // Encrypted string as Base64 decoder.
            cipher.init(Cipher.DECRYPT_MODE, sf.generateSecret(secretKey));
            plaintext = new String(cipher.doFinal(cipherBytes));  // Decrypt the original message.
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return plaintext;
    }
    
}

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {

    protected KeyPairGenerator kpg;
    protected KeyPair keyPair;
    protected PublicKey theirKey;
    protected KeyAgreement keyAgree;
    protected int KEYSIZE;

    public byte[] returnMyPublicKey() {
        return keyPair.getPublic().getEncoded();

    }

    public byte[] returnMyPrivateKey() {
        return keyPair.getPrivate().getEncoded();
    }

    public void setTheirPublicKey(byte[] theirs) {
        try {
            KeyFactory kef = KeyFactory.getInstance("RSA");
            this.theirKey = kef.generatePublic(new X509EncodedKeySpec(theirs));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public PublicKey returnTheirPublicKey() {
        return this.theirKey;
    }
}

class RSAKeyManager extends KeyManager {

    public RSAKeyManager(int keysize) {
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

    public byte[] encrypt_with_RSA(byte[] message) {
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

    public byte[] decrypte_with_RSA(byte[] message) {

        try {
            Cipher rsacipher = Cipher.getInstance("RSA");
            rsacipher.init(Cipher.DECRYPT_MODE, super.keyPair.getPrivate());

            return rsacipher.doFinal(message);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(RSAKeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public byte[] gen_DES_key() {
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

class DESEncryption {

    // private class fields
    private final String ENCRYPTION_ALGO = "DES/ECB/PKCS5Padding";
    private final int KEYSIZE = 8;
    private SecretKeySpec secretKey;
    private Cipher cipher;
    private byte[] key;

    // class constructor
    public DESEncryption(byte[] sharedkey) {
        if (sharedkey.length == KEYSIZE) {
            this.key = sharedkey;
        } else {
            this.key = new byte[KEYSIZE];
        }
        this.initCipher();
    }

    public byte[] getKey() {
        return this.key;
    }

    public boolean setKey(byte[] input) {
        if (input.length == KEYSIZE) {
            this.key = input;
            return true;
        }
        return false;
    }

    private void initCipher() {
        try {
            this.secretKey = new SecretKeySpec(this.key, 0, this.key.length, "ENCRYPTION_ALGO");
            cipher = Cipher.getInstance(ENCRYPTION_ALGO);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(DESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String encryptDES(String plaintext) {
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

    public String decryptDES(String ciphertext) {
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

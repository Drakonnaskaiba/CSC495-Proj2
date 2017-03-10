
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;


/*
This class will be responsible for the Key Management between the Client and
Server.

 */
public class Key_Management {

    private KeyPair key_pair;
    private KeyAgreement key_agreement;
  

    /**
     * Generates a Public Key
     * @param P
     * @param G
     * @return 
     */
    public byte[] generate_Public_Key(BigInteger P, BigInteger G) {
        try {
            DHParameterSpec diffie_helman_spec;
            

            diffie_helman_spec = new DHParameterSpec(P, G);

            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DiffieHellman");
            keygen.initialize(diffie_helman_spec);
            key_pair = keygen.generateKeyPair();
            key_agreement = KeyAgreement.getInstance("DiffieHellman");

            key_agreement.init(key_pair.getPrivate());

            BigInteger public_key = ((DHPublicKey) key_pair.getPublic()).getY();

            return public_key.toByteArray();

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            Logger.getLogger(Key_Management.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    
   

    /**
     * Computes the shared key
     * @param public_key
     * @param P
     * @param G
     * @return 
     */
    public byte[] compute_shared_key(byte[] public_key, BigInteger P, BigInteger G) {
        if (key_agreement == null) {
            return null;
        }

        try {
            KeyFactory keyfact = KeyFactory.getInstance("DiffieHellman");
            BigInteger biggie = new BigInteger(1, public_key);
            PublicKey bar_key = keyfact.generatePublic(new DHPublicKeySpec(biggie, P, G));
            key_agreement.doPhase(bar_key, true);
            byte[] sharedkeybyte = key_agreement.generateSecret();

            return sharedkeybyte;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | IllegalStateException ex) {
            Logger.getLogger(Key_Management.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
   
}

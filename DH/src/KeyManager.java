
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
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

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
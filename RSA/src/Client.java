
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPClient {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the RSA parameters.
        RSAKeyManager keyman = new RSAKeyManager(1024);

        // method fields used to hold strings to be read and written.
        String sentence;
        String modifiedSentence;

        // Readers and Writers used to communicate across TCP/IP connection.
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());

        // Key Agreement
        byte[] message = keyman.returnMyPublicKey();
        outToServer.writeUTF(new String(Base64.getEncoder().encode(message)));
        String key = inFromServer.readUTF();
        byte[] theirKey = Base64.getDecoder().decode(key);
        keyman.setTheirPublicKey(theirKey);

        // Generate and Encrypt a secret key.
        byte[] shared_secret = keyman.gen_DES_key();
        byte[] e_shared_secret = keyman.encrypt_with_RSA(shared_secret);
        outToServer.writeUTF(new String(Base64.getEncoder().encode(e_shared_secret)));

        System.out.println(new String(Base64.getEncoder().encode(shared_secret)));

        // Create new DES enctryption object and use it for the session.
        DESEncryption encrypter = new DESEncryption(shared_secret);

        sentence = inFromUser.readLine();
        outToServer.writeUTF(encrypter.encryptDES(sentence));
        modifiedSentence = encrypter.decryptDES(inFromServer.readUTF());
        System.out.println("FROM SERVER: " + modifiedSentence);
        clientSocket.close();
    }
}

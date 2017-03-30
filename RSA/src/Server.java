
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPServer {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the RSA parameters.
        RSAKeyManager keyman = new RSAKeyManager(1024);

        // method fields used to hold strings to be read and written.
        String clientSentence;
        String capitalizedSentence;

        // Declare and initialize the server socket to listen on port 6789.
        ServerSocket welcomeSocket = new ServerSocket(6789);
        System.out.println("Listening for connection on port 6789");

        while (true) {
            Socket connectionSocket = welcomeSocket.accept();
            System.out.println("Incoming connection received");

            // Once a connection has been established, create the readers and writers used to communicate across TCP/IP connection.
            DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());

            // Perform Key Agreement.
            String key = inFromClient.readUTF();
            byte[] theirKey = Base64.getDecoder().decode(key);
            keyman.setTheirPublicKey(theirKey);
            byte[] my_key = keyman.returnMyPublicKey();
            outToClient.writeUTF(new String(Base64.getEncoder().encode(my_key)));

            // Decrypt and display shared secret.
            String secret = inFromClient.readUTF();
            byte[] e_shared_secret = Base64.getDecoder().decode(secret);
            byte[] shared_secret = keyman.decrypte_with_RSA(e_shared_secret);
            System.out.println(new String(Base64.getEncoder().encode(shared_secret)));

            // Continue with RSA encryption/decryption.
            String sent = inFromClient.readUTF();
            byte[] mess = Base64.getDecoder().decode(sent);
            clientSentence = new String(keyman.decrypte_with_RSA(mess));
            System.out.println("Received from Client: " + clientSentence);
            capitalizedSentence = clientSentence.toUpperCase();
            byte[] backBytes = capitalizedSentence.getBytes();
            outToClient.writeUTF(new String(Base64.getEncoder().encode(keyman.encrypt_with_RSA(backBytes))));
            
            String[] encrypted = new String[9914];
            for (int c=0; c < 9914;c++){
                encrypted[c] = inFromClient.readUTF();
            }
            
            System.out.println("Start decryption of word list.");
            String[] decrypted = testRSADecrytion(encrypted, keyman);
            System.out.println("Decryption finished.");
        }
    }
    
    
    // separate static class used for speed testing RSA decrytion using the Profiler.
    public static String[] testRSADecrytion(String[] wordList, RSAKeyManager keyman){
        String[] decrypted = new String[wordList.length];
        for (int c = 0;c < wordList.length;c++){
            decrypted[c] = new String(keyman.decrypte_with_RSA(Base64.getDecoder().decode(wordList[c])));
        }
        return decrypted;
    }
}

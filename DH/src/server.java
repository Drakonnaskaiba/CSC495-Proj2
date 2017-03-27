
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPServer {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the Diffie-Hellman parameters.
        DHKeyManager keyman2 = new DHKeyManager(1024);

        // method fields used to hold strings to be read and written.
        String clientSentence;
        String capitalizedSentence;

        // Declare and initialize the server socket to listen on port 6789.
        ServerSocket welcomeSocket = new ServerSocket(6789);
        System.out.println("Listening for connection on port 6789");

        while (true) {
            Socket connectionSocket = welcomeSocket.accept();
            System.out.println("Connection received.");

            // Once a connection has been established, create the readers and writers used to communicate across TCP/IP connection.
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());

            // Perform Key Agreement.
            String key = inFromClient.readUTF();
            byte[] theirKey = Base64.getDecoder().decode(key);
            keyman2.setTheirPublicKey(theirKey);
            keyman2.setDHParameterSpec();
            byte[] myKey = keyman2.returnMyPublicKey();
            outToClient.writeUTF(new String(Base64.getEncoder().encode(myKey)));

            // Compute shared secret.
            byte[] outputB = keyman2.computeSharedSecret();

            // Use last 8 bytes of shared secret as the DES key.
            byte[] DESKey = new byte[8];
            int start = outputB.length - 8;
            for (int c = start; c < outputB.length; c++) {
                DESKey[c - start] = outputB[c];
            }

            // Create new DES enctryption object and use it for the session.
            DESEncryption encrypter = new DESEncryption(DESKey);

            clientSentence = encrypter.decryptDES(inFromClient.readUTF());
            System.out.println("Received from Client: " + clientSentence);
            capitalizedSentence = clientSentence.toUpperCase();
            outToClient.writeUTF(encrypter.encryptDES(capitalizedSentence));
            
            String[] encrypted = new String[9914];
            for (int c=0; c < 9914;c++){
                encrypted[c] = inFromClient.readUTF();
            }
            
            System.out.println("Start decryption of word list.");
            String[] decrypted = testDESDecrytion(encrypted, encrypter);
            System.out.println("Decryption finished.");
        }
    }
    
    // separate static class used for speed testing RSA decrytion using the Profiler.
    public static String[] testDESDecrytion(String[] wordList, DESEncryption encrypter){
        String[] decrypted = new String[wordList.length];
        for (int c = 0;c < wordList.length;c++){
            decrypted[c] = encrypter.decryptDES(wordList[c]);
        }
        return decrypted;
    }
}

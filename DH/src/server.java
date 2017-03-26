
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

            // Display shared secrete.
            byte[] outputB = keyman2.computeSharedSecret();
            String encoded = new String(Base64.getEncoder().encode(outputB));
            System.out.println("Computed Shared Secret: ");
            System.out.println(encoded);
            //capitalizedSentence = clientSentence.toUpperCase() + '\n';
            //outToClient.writeBytes(capitalizedSentence);
        }
    }
}


import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPClient {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the Diffie-Hellman parameters.
        DHKeyManager keyman1 = new DHKeyManager(1024);
        keyman1.generateParameters();
        
        // method fields used to hold strings to be read and written.
        String sentence;
        String modifiedSentence;
        
        // Readers and Writers used to communicate across TCP/IP connection.
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
        
        // Key Agreement
        byte[] message = keyman1.returnMyPublicKey();
        outToServer.writeUTF(new String(Base64.getEncoder().encode(message)));
        String key = inFromServer.readUTF();
        byte[] theirKey = Base64.getDecoder().decode(key);
        keyman1.setTheirPublicKey(theirKey);
        byte[] outputA = keyman1.computeSharedSecret();
        
        // Displays the output of the Key Agreement.
        String encoded = new String(Base64.getEncoder().encode(outputA));
        System.out.println("Computed Shared Secret: ");
        System.out.println(encoded);
        //sentence = inFromUser.readLine();
        //outToServer.writeBytes(sentence + '\n');
        //modifiedSentence = inFromServer.readLine();
        //System.out.println("FROM SERVER: " + modifiedSentence);
        clientSocket.close();
    }
}

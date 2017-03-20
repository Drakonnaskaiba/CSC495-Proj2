
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPServer {

    public static void main(String argv[]) throws Exception {
        DHKeyManager keyman2 = new DHKeyManager(1024);
        String clientSentence;
        String capitalizedSentence;
        ServerSocket welcomeSocket = new ServerSocket(6789);
        System.out.println("Listening for connection on port 6789");

        while (true) {
            Socket connectionSocket = welcomeSocket.accept();
            System.out.println("Connection received.");
            //BufferedReader inFromClient
                    //= new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
            int length = inFromClient.readInt();
            byte[] theirKey = new byte[length];
            inFromClient.readFully(theirKey, 0, theirKey.length);
            //clientSentence = inFromClient.readLine();
            keyman2.setTheirPublicKey(theirKey);
            keyman2.setDHParameterSpec();
            byte[] myKey = keyman2.returnMyPublicKey();
            outToClient.writeInt(myKey.length);
            outToClient.write(myKey);
            byte[] outputB = keyman2.computeSharedSecret();
            String encoded = new String(Base64.getEncoder().encode(outputB));
            System.out.println("Computed Shared Secret: ");
            System.out.println(encoded);
            //capitalizedSentence = clientSentence.toUpperCase() + '\n';
            //outToClient.writeBytes(capitalizedSentence);
        }
    }
}

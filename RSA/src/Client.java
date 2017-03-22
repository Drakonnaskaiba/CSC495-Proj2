import java.io.*;
import java.net.*;
 
class TCPClient
{
 public static void main(String argv[]) throws Exception
 {
     RSAKeyManager keyman = new RSAKeyManager(2048);
     
     
  String sentence;
  String modifiedSentence;
  BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));
  Socket clientSocket = new Socket("localhost", 6789);
  DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
  DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
  //BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
     
  byte[] message = keyman.returnMyPublicKey();
  
  outToServer.write(message.length);
     System.out.println("sent message length");
  outToServer.write(message);
  int msglength = inFromServer.readInt();
  byte[] theirKey = new byte[msglength];
  inFromServer.readFully(theirKey, 0, theirKey.length);
  keyman.setTheirPublicKey(theirKey);
  
     System.out.println("Received Server's Key");
  
  byte[] shared_secret = keyman.gen_DES_key();
  
  byte[] e_shared_secret = keyman.encrypt_with_RSA(shared_secret);
  outToServer.write(e_shared_secret.length);
  outToServer.write(e_shared_secret);
  
  System.out.println(new String(shared_secret));
  
  
  sentence = inFromUser.readLine();
  outToServer.writeBytes(sentence + '\n');
  modifiedSentence = inFromServer.readLine();
  System.out.println("FROM SERVER: " + modifiedSentence);
  clientSocket.close();
 }
}
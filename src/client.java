import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

class TCPClient
{
    static byte[] public_key;
    static BigInteger P;
    static BigInteger G;
            
 public static void main(String argv[]) throws Exception
 {
     final int keysize = 1024;

            SecureRandom secrand = new SecureRandom();
            P = BigInteger.probablePrime(keysize / 2, secrand);
            G = BigInteger.probablePrime(keysize / 2, secrand);
     
     Key_Management keyman = new Key_Management();
     public_key = keyman.generate_Public_Key(P, G);
     
  String sentence;
  String modifiedSentence;
  BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));
  Socket clientSocket = new Socket("localhost", 6789);
  DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
  BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
  
 
  byte[] pbyte = P.toByteArray();
  byte[] gbyte = G.toByteArray();
  
   Encoder e = Base64.getEncoder();
  outToServer.writeBytes(new String(e.encode(pbyte))+"\n");
  outToServer.writeBytes(new String(e.encode(gbyte))+"\n");
  
  
  
  
  //String string_key = new String(public_key);
 
  outToServer.writeBytes(new String(e.encode(public_key))+"\n");
  System.out.println("Sent public key");
  
  
  
  
  
  String Bob_key = inFromServer.readLine();
  Decoder d = Base64.getDecoder();
  byte[] Bob_byte_key = d.decode(Bob_key);
  
     System.out.println(Bob_key);
     
  
  byte[] sharedsecret = keyman.compute_shared_key(Bob_byte_key, P, G);
  
     for (int c=0;c<sharedsecret.length;c++){
                System.out.print(sharedsecret[c]);
            }
  
  
  
  
  
  
  
  
//  sentence = inFromUser.readLine();
//  outToServer.writeBytes(sentence + '\n');
//  modifiedSentence = inFromServer.readLine();
//  System.out.println("FROM SERVER: " + modifiedSentence);
  clientSocket.close();
 }
}
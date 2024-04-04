import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) throws IOException {
        try {
            Socket socket = new Socket("localhost", 1234);

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

            PublicKey serverPublicKey = (PublicKey) inputStream.readObject();

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            outputStream.writeObject(keyPair.getPublic());
            outputStream.flush();

            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));

            String inputLine;
            while ((inputLine = consoleInput.readLine()) != null) {
                byte[] encryptedMessage = encryptCipher.doFinal(inputLine.getBytes());
                outputStream.writeObject(encryptedMessage);
                outputStream.flush();

                byte[] encryptedResponse = (byte[]) inputStream.readObject();
                String decryptedResponse = new String(decryptCipher.doFinal(encryptedResponse));
                System.out.println("Server: " + decryptedResponse);
            }

            inputStream.close();
            outputStream.close();
            socket.close();
        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}
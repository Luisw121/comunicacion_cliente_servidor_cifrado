import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

public class Client {

    public static void main(String[] args) throws IOException {
        try {

            Socket socket = new Socket("localhost", 1234);

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair clientKeyPair = keyGen.generateKeyPair();
            outputStream.writeObject(clientKeyPair.getPublic());
            outputStream.flush();

            PublicKey serverPublicKey = (PublicKey) inputStream.readObject();

            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, clientKeyPair.getPrivate());
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            Thread readThread = new Thread(() -> {
                try {

                    while (true) {

                        byte[] encryptedMessage = (byte[]) inputStream.readObject();
                        String decryptedMessage = new String(decryptCipher.doFinal(encryptedMessage));
                        System.out.println("Server: " + decryptedMessage);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            readThread.start();

            BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));

            String inputLine;
            while ((inputLine = consoleInput.readLine()) != null) {

                byte[] encryptedMessage = encryptCipher.doFinal(inputLine.getBytes());
                outputStream.writeObject(encryptedMessage);
                outputStream.flush();
            }

            inputStream.close();
            outputStream.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

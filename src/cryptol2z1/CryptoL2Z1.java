package cryptol2z1;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

/**
 *
 * @author Patryk Kozieł
 */
public class CryptoL2Z1 {

    private static void setUpProperties() throws FileNotFoundException, IOException {
        
        Properties properties = new Properties();
        FileReader fileReader = new FileReader("src\\cryptol2z1\\prop.properties");
        properties.load(fileReader);
        
        password = properties.getProperty("keystore_password");
        modeOfEncryption = properties.getProperty("enc_mode");
        keystorePath = properties.getProperty("keystore_path");
        keyIdentifier = properties.getProperty("key_identifier");
        pathToFile = properties.getProperty("path_to_file");
    }
    
    static String keyIdentifier;
    static String password;
    static String modeOfEncryption;
    static String keystorePath;
    static String pathToFile;
    

    public static void main(String[] args) throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        //Mode 0: encrypt file
        //Mode 1: decrypt file
        //Mode 2: encryption oracle
        //Mode 3: challange
        //Mode 4: CPA attack
        
        setUpProperties();
        
        System.out.println("Mode: " + args[0] + " args length: " + args.length);
        
        byte[] file;
        
        switch (args[0]) {
            case "0":
                file = Files.readAllBytes(Paths.get(pathToFile));
                encryptFile(file);
                break;
            case "1":
                file = Files.readAllBytes(Paths.get(pathToFile));
                decryptFile(file);
                break;
            case "2":
                for (int i = 1; i < args.length; i++){
                    System.out.println(encryptMessage(args[i]));
                }
                break;
            case "3":
               Random generator = new Random();
               System.out.println(encryptMessage(args[generator.nextInt(2)+1]));
               break;
            case "4":
                runCPA();
            default:
                break;
        }
    }

    private static String encryptMessage(String arg) throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        byte[] msg = arg.getBytes();
        
        MyCipher myCipher;
        
            myCipher = new MyCipher(
                    msg,
                    modeOfEncryption,
                    keystorePath,
                    keyIdentifier,
                    password
            );
                
        return new String(myCipher.encrypt());
    }

    private static void decryptFile(byte[] file) throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException {
        MyCipher myCipher;
        
            myCipher = new MyCipher(
                    file,
                    modeOfEncryption,
                    keystorePath,
                    keyIdentifier,
                    password
            );
            
            try {
            byte[] decrypted = myCipher.decrypt();
            FileOutputStream fos = new FileOutputStream("decryptedFile");
            fos.write(decrypted);
            fos.close();
        } catch (BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | UnrecoverableKeyException ex) {
            Logger.getLogger(CryptoL2Z1.class.getName()).log(Level.SEVERE, null, ex);
        }
               
    }
    
        private static void encryptFile(byte[] file) throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, UnrecoverableKeyException, IllegalBlockSizeException {
        MyCipher myCipher;
        
            myCipher = new MyCipher(
                    file,
                    modeOfEncryption,
                    keystorePath,
                    keyIdentifier,
                    password
            );
            
 
        try {
            byte[] encrypted = myCipher.encrypt();
            FileOutputStream fos = new FileOutputStream("encryptedFile");
            fos.write(encrypted);
            fos.close();
        } catch (BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(CryptoL2Z1.class.getName()).log(Level.SEVERE, null, ex);
        }             
    }

    private static void runCPA() throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException {
       
        ArrayList<Byte[]> messages = new ArrayList<Byte[]>();
        byte[] msg1 = new byte[16];
        byte[] msg2 = new byte[16];
        
        Random generator = new Random();
        generator.nextBytes(msg1);
        generator.nextBytes(msg2);
        
        printMsg(msg1);
        printMsg(msg2);
        
        byte[] msg = new byte[16];
        
        if (generator.nextInt(2)==0){
            msg = msg1;
        } else {
            msg = msg2;
        }
        
        MyCipher myCipher = new MyCipher(
                msg,
                modeOfEncryption,
                keystorePath,
                keyIdentifier,
                password
            );
                
        CPAPair pair1 = myCipher.CPAround(1, msg);
        System.out.println("IV: "); printMsg(pair1.IV);
        System.out.println("Encrypted: "); printMsg(pair1.encryptedMsg);
        
        byte[] newIv = increase(pair1.IV);
        System.out.println("Increased IV: "); printMsg(newIv);
        
        byte[] myMessage = ByteUtils.xor(pair1.IV, newIv);
        System.out.println("Xored IV's: "); printMsg(myMessage);
        
        myMessage = ByteUtils.xor(myMessage, msg1);
        System.out.println("Xored IV's and Message 1: "); printMsg(myMessage);
        
        CPAPair pair2 = myCipher.CPAround(2, myMessage);
        System.out.println("Obtained ciphertext: "); printMsg(pair2.encryptedMsg);
        
        if(Arrays.equals(pair1.encryptedMsg, pair2.encryptedMsg)){
            System.out.println("We claim that encrypted msg was msg1: ");
            printMsg(msg1);
        } else {
            System.out.println("We claim that encrypted msg was msg2: ");
            printMsg(msg2); 
        }
        
        System.out.println("Message really encrypted: ");
        printMsg(myCipher.secretmsg);
    }
    
    public static void printMsg(byte[] msg){
        for (int j = 0; j < 16; j++){
            System.out.print(msg[j]);
            if (j == 15) System.out.println();
            else System.out.print(",");
        }
    }

    private static byte[] increase(byte[] iv) {
        byte[] res = iv.clone();
        int changeByte = (int) iv[iv.length-1];
        changeByte = (byte) changeByte + 1;
        
        res[iv.length - 1] = (byte) changeByte;
        return res;
    }

        
    
    
}

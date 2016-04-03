/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import cryptol2z1.MyCipher;
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
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Patryk Kozieł
 */
public class cryptoL2Z1Test {
    
    public cryptoL2Z1Test() {
    }
    
    @Test
    public void testOFB() throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        
        byte[] myFile = Files.readAllBytes(Paths.get("D:\\Studia\\Crypto\\L2\\to_encrypt_ofb.txt"));
        MyCipher myCipher = new MyCipher
                        (
                            myFile,
                            "OFB",
                            "D:\\Studia\\Crypto\\L2\\keystore\\ks.jck",
                            "key1",
                            "password");
        
        
        byte[] encrypted = myCipher.encrypt();
        
        MyCipher myCipherDecryption = new MyCipher
                        (
                            encrypted,
                            "OFB",
                            "D:\\Studia\\Crypto\\L2\\keystore\\ks.jck",
                            "key1",
                            "password");
        
        byte[] decrypted = myCipherDecryption.decrypt();
        
        assertFalse(Arrays.equals(encrypted,decrypted));
        assertTrue(Arrays.equals(myFile, decrypted));
    }
    
    @Test
    public void testCTR() throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        
                byte[] myFile = Files.readAllBytes(Paths.get("D:\\Studia\\Crypto\\L2\\to_encrypt_ofb.txt"));
         MyCipher myCipher = new MyCipher
                        (
                            myFile,
                            "CTR",
                            "D:\\Studia\\Crypto\\L2\\keystore\\ks.jck",
                            "key1",
                            "password");
        
        
        byte[] encrypted = myCipher.encrypt();
        
        MyCipher myCipherDecryption = new MyCipher
                        (
                            encrypted,
                            "CTR",
                            "D:\\Studia\\Crypto\\L2\\keystore\\ks.jck",
                            "key1",
                            "password");
        
        byte[] decrypted = myCipherDecryption.decrypt();
        
        assertFalse(Arrays.equals(encrypted,decrypted));
        assertTrue(Arrays.equals(myFile, decrypted));
    }
    
    @Test
    public void testCBC() throws KeyStoreException, IOException, MalformedURLException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        
                byte[] myFile = Files.readAllBytes(Paths.get("D:\\Studia\\Crypto\\L2\\to_encrypt_ofb.txt"));
         MyCipher myCipher = new MyCipher
                        (
                            myFile,
                            "CBC",
                            "D:\\Studia\\Crypto\\L2\\keystore\\ks.jck",
                            "key1",
                            "password");
        
        
        byte[] encrypted = myCipher.encrypt();
        
        MyCipher myCipherDecryption = new MyCipher
                        (
                            encrypted,
                            "CBC",
                            "D:\\Studia\\Crypto\\L2\\keystore\\ks.jck",
                            "key1",
                            "password");
        
        byte[] decrypted = myCipherDecryption.decrypt();
        
        assertFalse(Arrays.equals(encrypted,decrypted));
        assertTrue(Arrays.equals(myFile, decrypted));
    }

}

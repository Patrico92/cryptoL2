package cryptol2z1;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Patryk Kozieł
 */
public class MyCipher {

    String modeOfEncryption;
    String keystorePath;
    String keyIdentifier;
    String password;
    KeyStore keystore;
    String keyStoreType = "JCEKS";
    Cipher cipher;
    byte[] fileBytes;
    byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    IvParameterSpec ivspec;
    byte[] secretmsg;

    public MyCipher(byte[] fileBytes, String modeOfEncryption, String keystorePath, String keyIdentifier, String password) throws MalformedURLException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        this.fileBytes = fileBytes;
        this.modeOfEncryption = modeOfEncryption;
        this.keystorePath = keystorePath;
        this.keyIdentifier = keyIdentifier;
        this.password = password;
        ivspec = new IvParameterSpec(iv);
        
        initializeKeyStore();

        cipher = Cipher.getInstance("AES/"+modeOfEncryption + (modeOfEncryption.equals("CBC") ? "/PKCS5Padding" : "/NoPadding"));
        
    }

    private void initializeKeyStore() throws MalformedURLException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        
        File keystoreFile = new File(keystorePath);
        final URL keystoreURL = keystoreFile.toURI().toURL();
        
        keystore = KeyStore.getInstance(keyStoreType);
        InputStream is = keystoreURL.openStream();
        keystore.load(is, password.toCharArray());
        
    }
    
    public byte[] encrypt() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{ 
        cipher.init(Cipher.ENCRYPT_MODE, keystore.getKey(keyIdentifier, password.toCharArray()),ivspec);
        return cipher.doFinal(fileBytes);
        
    }
    
    public byte[] decrypt() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidAlgorithmParameterException{
        Key key = keystore.getKey(keyIdentifier, password.toCharArray());

        cipher.init(Cipher.DECRYPT_MODE, key,ivspec);
        return cipher.doFinal(fileBytes);
    }
    
    public CPAPair CPAround(int roundNumber, byte[] msg) throws KeyStoreException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException{
        
        CPAPair cpaPair = null;
        
        if (roundNumber == 1){
            secretmsg = msg;
            iv = generateSomeIV();
            ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keystore.getKey(keyIdentifier, password.toCharArray()),ivspec);
            cpaPair = new CPAPair(cipher.doFinal(msg), iv);
        } else if (roundNumber == 2) {
            iv = increase(iv);
            ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keystore.getKey(keyIdentifier, password.toCharArray()),ivspec);
            cpaPair = new CPAPair(cipher.doFinal(msg), iv);
        }
        return cpaPair;    
    }

    private byte[] generateSomeIV() {
        byte[] ivRandom = new byte[16];
        Random generator = new Random();
        
        generator.nextBytes(ivRandom);
        return ivRandom;
    }

    private byte[] increase(byte[] iv) {
        int changeByte = (int) iv[iv.length-1];
        changeByte = (byte) changeByte + 1;
        
        iv[iv.length - 1] = (byte) changeByte;
        return iv;
    }

}

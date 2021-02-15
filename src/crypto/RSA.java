package crypto;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.util.Arrays;

public class RSA {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    
    public static byte[] RSAencrypt(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText);

        return cipherText;
    }

    public static byte[] RSAdecrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
       // byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        System.out.println("Vystup z RSA: " + Arrays.toString(decriptCipher.doFinal(cipherText)));
        return decriptCipher.doFinal(cipherText);
    }

    public static void saveKeyToFile(File file, byte[] key) throws IOException{        
        FileOutputStream outputStream = new FileOutputStream(file);;
        outputStream.write(key);

        outputStream.close();
    }
    public static KeyPair loadKeyPairFromDB(byte[] pukbytes, byte[] prkbytes) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException, SQLException {
        PKCS8EncodedKeySpec pcks = new PKCS8EncodedKeySpec(prkbytes);
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(pukbytes);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PrivateKey PRK = kf.generatePrivate(pcks);
        PublicKey PUK = kf.generatePublic(x509);

        return new KeyPair(PUK, PRK);

    }
    
    public static KeyPair loadKeyPairFromFile() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File prkfile = new File("PRIVATE_KEY");
        File pukfile = new File("PUBLIC_KEY");
        byte[] pukbytes = new byte[(int)pukfile.length()];
        byte[] prkbytes = new byte[(int)prkfile.length()];
        
        FileInputStream fileInputStreamPU = new FileInputStream(pukfile);
        FileInputStream fileInputStreamPR = new FileInputStream(prkfile);
        fileInputStreamPU.read(pukbytes);
        fileInputStreamPR.read(prkbytes);
        fileInputStreamPR.close();
        fileInputStreamPU.close();
        
        PKCS8EncodedKeySpec pcks = new PKCS8EncodedKeySpec(prkbytes);
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(pukbytes);
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        PrivateKey PRK = kf.generatePrivate(pcks);
        PublicKey PUK = kf.generatePublic(x509);
        
        return new KeyPair(PUK, PRK);
        
    }
}
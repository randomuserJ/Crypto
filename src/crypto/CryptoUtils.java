package crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class CryptoUtils
{
	private static final String ALGORITHM="AES";
	private static final String TRANSFORMATION="AES/CTR/PKCS5Padding";


	public static void encrypt(File inputFile, File outputFile,  byte[] pubkey, byte[] privkey) throws Exception
	{		
		byte[] key = null;
		byte[] iv = generateSecretKey(128).getEncoded();
		
		doCrypto(Cipher.ENCRYPT_MODE, key, iv, inputFile, outputFile, pubkey, privkey);
		
		FileUtils.signFile(outputFile);
		System.out.println("Sifrovanie hotove");
	}

	public static void decrypt(File inputFile, File outputFile, byte[] pubkey, byte[] privkey) throws Exception
	{
		if (compareMacs(inputFile)) {
			byte[][] keyandiv = parseHead(inputFile);
			inputFile = FileUtils.cutFile(inputFile);
			doCrypto(Cipher.DECRYPT_MODE, keyandiv[0], keyandiv[1], inputFile, outputFile, pubkey, privkey);
		} else {
			System.out.println("Nezhoduje sa MAC");
		}
		
	}
	
	
	private static void doCrypto(int cipherMode, byte[] key, byte[] iv, File inputFile, 
			File outputFile, byte[] pubkey, byte[] privkey) throws Exception
	{
		boolean addHDR = true;
		//iv=DatatypeConverter.parseHexBinary("064df9633d9f5dd0b5614843f6b4b059");

		try{
			Key secretKey = null;
	        if (key != null){
	        	secretKey = new SecretKeySpec(key, ALGORITHM);	        	
	        } else 	
	        	secretKey = generateSecretKey(256);
	        
	        System.out.println("Key before ENC: " + Arrays.toString(secretKey.getEncoded()));

	        /*Created one more function to be able to read the keys from DB*/
	        //KeyPair pair = RSA.loadKeyPairFromFile();
			KeyPair pair = RSA.loadKeyPairFromDB(pubkey, privkey);
	        byte[] cipherText = null;
	        byte[] decipheredMessage = null;
	        
	        //Encrypt the message
	        try {
	        	cipherText = RSA.RSAencrypt(secretKey.getEncoded(), pair.getPublic());
	        	decipheredMessage = RSA.RSAdecrypt(cipherText, pair.getPrivate());
	        } catch(Exception e) {

	        	cipherText = secretKey.getEncoded();

	        	
	        	decipheredMessage = RSA.RSAdecrypt(cipherText, pair.getPrivate());
	        	secretKey = new SecretKeySpec(decipheredMessage, ALGORITHM);
	        	addHDR = false;
	        }
	        
	        System.out.println("Key after DEC: " + Arrays.toString(decipheredMessage));
	        
	        
	        System.out.println("iv: "+Arrays.toString(iv));
			IvParameterSpec ivParameterSpec=new IvParameterSpec(iv);
			
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			System.out.println("1: " + Arrays.toString(secretKey.getEncoded()));
			System.out.println("2: " + Arrays.toString(ivParameterSpec.getIV()));
			cipher.init(cipherMode, secretKey, ivParameterSpec);
			
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int)inputFile.length()];
			inputStream.read(inputBytes);

			byte[] outputBytes = cipher.doFinal(inputBytes);
			
			FileOutputStream outputStream = new FileOutputStream(outputFile);
				
			if (addHDR) {
				int length = cipherText.length;
				byte[] lengthBytes = Integer.toString(length).getBytes();
				System.out.println("KEYLNG: " + Arrays.toString(lengthBytes));
				System.out.println("KEY: " + Arrays.toString(cipherText));
				System.out.println("IV: " + Arrays.toString(ivParameterSpec.getIV()));
				System.out.println("FILE: " + Arrays.toString(Arrays.copyOfRange(outputBytes, 0, 20)));
				
				outputStream.write(lengthBytes);
				outputStream.write(cipherText);
				outputStream.write(ivParameterSpec.getIV());
			}
			outputStream.write(outputBytes);
			
			inputStream.close();
			outputStream.close();
		}
		catch(NoSuchPaddingException | NoSuchAlgorithmException
		| InvalidKeyException | BadPaddingException
		| IllegalBlockSizeException | IOException ex)
		{
			throw new Exception("Errorencrypting/decryptingfile"+ex.getMessage(),ex);
		}
	}

	public static byte[] MAC(byte[] input, SecretKey key) throws Exception{
	
	  //Creating a Mac object
	  Mac mac = Mac.getInstance("HmacSHA256");
	
	  //Initializing the Mac object
	  mac.init(key);
	
	  //Computing the Mac
	  byte[] macResult = mac.doFinal(input);
	
	  //System.out.println("This came: "+Arrays.toString(input));
	  System.out.println("MAC Key: "+Arrays.toString(key.getEncoded())+", "+key.getEncoded().length);
	  System.out.println("Mac result:");
	  System.out.println(new String(macResult));
	  System.out.println(Arrays.toString(macResult));
	  System.out.println(macResult.length);
	  return macResult;
   }


	private static boolean compareMacs(File inputFile) throws Exception {
		FileInputStream inputStream = new FileInputStream(inputFile);
		byte[] inputBytes = new byte[(int)inputFile.length()];
		inputStream.read(inputBytes);
	/*
		byte[] size = Arrays.copyOfRange(inputBytes, 0, 3);
		int keysize = Integer.parseInt(new String(size));
		
		byte[] symkey = Arrays.copyOfRange(inputBytes, 3, 3+keysize);					// ?? bit (cca 256)
		byte[] iv = Arrays.copyOfRange(inputBytes, 3+keysize, 3+keysize+16);			// 16 bit
		byte[] mac = Arrays.copyOfRange(inputBytes, 3+keysize+16, 3+keysize+48);		// 32 bit
		byte[] mackey = Arrays.copyOfRange(inputBytes, 3+keysize+48, 3+keysize+64);		// 16 bit
		byte[] file = Arrays.copyOfRange(inputBytes, 3+keysize+64, inputBytes.length);
	*/	
		byte[] mac = Arrays.copyOfRange(inputBytes, 0, 32);			// 32 bit
		byte[] mackey = Arrays.copyOfRange(inputBytes, 32, 48);		// 16 bit
		byte[] file = Arrays.copyOfRange(inputBytes, 48, inputBytes.length);
		
		SecretKey secretKey = new SecretKeySpec(mackey, "AES");
		byte[] MACfile = MAC(file,secretKey);
		
		System.out.println("MAC: " + Arrays.toString(mac));
		System.out.println("KEY: " + Arrays.toString(mackey));
		System.out.println(new String(mac));
		System.out.println(new String(MACfile));
		
		inputStream.close();
		if(Arrays.equals(mac, MACfile))
			return true;
		return false;
	}
	
	private static byte[][] parseHead(File file) throws IOException {
		byte[][] keyandiv = new byte[2][];
		
		FileInputStream inputStream = new FileInputStream(file);
		byte[] inputBytes = new byte[(int)file.length()];
		inputStream.read(inputBytes);
		
		byte[] keysizeBytes = Arrays.copyOfRange(inputBytes, 48, 48+3);
		int keysize = Integer.parseInt(new String(keysizeBytes));
		
		byte[] keyByteArray = Arrays.copyOfRange(inputBytes,  48+3, 48+3+keysize);
		byte[] ivByteArray = Arrays.copyOfRange(inputBytes, 48+3+keysize, 48+3+keysize+16);
		System.out.println("key from dec file: " + Arrays.toString(keyByteArray));
		System.out.println("iv from dec file: " + Arrays.toString(ivByteArray));
		
		keyandiv[0] = keyByteArray;
		keyandiv[1] = ivByteArray;
		inputStream.close();
		return keyandiv;
	}

	public static SecretKey generateSecretKey(int keySize) throws NoSuchAlgorithmException {

		KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);

		  //Creating a SecureRandom object
		  SecureRandom secRandom = new SecureRandom();
		
		  //Initializing the KeyGenerator
		  keyGen.init(keySize,secRandom);
		
		  //Creating/Generating a key
		  return keyGen.generateKey();
	}

	

}

	



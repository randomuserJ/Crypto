package crypto;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class FileUtils {
	public static void signFile(File encryptedFile) throws Exception {
		
		FileInputStream inputStream = new FileInputStream(encryptedFile);
		byte[] inputBytes = new byte[(int)encryptedFile.length()];
		inputStream.read(inputBytes);
		
		SecretKey MACkey = CryptoUtils.generateSecretKey(128);
		byte[] mac = CryptoUtils.MAC(inputBytes, MACkey);

		inputStream.close();
		
		FileOutputStream outputStream = new FileOutputStream(encryptedFile);
		outputStream.write(mac);
		outputStream.write(MACkey.getEncoded());
		outputStream.write(inputBytes);
		
		
		outputStream.close();
	}

	public static File cutFile(File file) throws IOException {
		File newFile = new File(File.separator + "shortened.tmp");
		newFile.createNewFile();
		
		FileInputStream inputStream = new FileInputStream(file);
		byte[] inputBytes = new byte[(int)file.length()];
		inputStream.read(inputBytes);
		
		byte[] keysizeBytes = Arrays.copyOfRange(inputBytes, 48, 48+3);
		int keysize = Integer.parseInt(new String(keysizeBytes));
		
		byte[] reducedByteArray = Arrays.copyOfRange(inputBytes, 48+3+keysize+16, inputBytes.length);
		
		FileOutputStream outputStream = new FileOutputStream(newFile);
		outputStream.write(reducedByteArray);
		inputStream.close();
		outputStream.close();
		
		return newFile;
	}

}

	

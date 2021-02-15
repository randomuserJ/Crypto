package crypto;
import com.example.demo.SpringContext;
import org.springframework.beans.factory.annotation.Autowired;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.regex.Pattern;

public class PasswordController {
//    private final String DICT_PATH = "D:\\Jozef\\IntelliJ IDEA Projects\\hash\\src\\dictionary_long.txt";
//    private final String DICT_PATH = "src/main/resources/dictionaries/dictionary.long.txt";
    private final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";
    public final Pattern passwordPattern = Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[.,@$!#@$^*%?&])[A-Za-z\\d.,@$!#@$^*%?&]{8,}$");
//    private ArrayList<String> dictionary;
    private String password;

    @Autowired
    PasswordUtils passwordUtils;

    public PasswordController(String password) {
        this.password = password;
    }

    public String verifyStrength(){
        System.out.println(password);
        if(!passwordPattern.matcher(password).matches()){
            return "Password must contains at least eight characters, one uppercase letter, one lowercase letter, one number and one special character (. , @ $ ! % * ? &).";
        }

        if(SpringContext.getBean(PasswordUtils.class).validPassword(password) == false){
            return "Password is one of the most common passwords! Please use another.";
        }

        return "OK";
    }


    public byte[] generateSalt(){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32];
        random.nextBytes(salt);
        return salt;
    }

    public byte[] compute_hash( byte[] salt) {

        byte[] hash = null;
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            hash = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex){
            ex.printStackTrace();
        }

        return hash;
    }
}

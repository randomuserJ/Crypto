package crypto;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;


public class PasswordUtils {

    private ArrayList<String> dictionary;
    private String DICT_PATH = "src/dictionary.txt";

    public boolean validPassword(String password){

        if (this.dictionary.contains(password.toLowerCase())) {
            return false;
        } else {
            return true;
        }
    }

    public PasswordUtils(){

        BufferedReader reader;
        ArrayList<String> commonPasswords = new ArrayList<String>();
        try {
            reader = new BufferedReader(new FileReader(
                    DICT_PATH));
            String line = reader.readLine();
            while (line != null) {
                line = reader.readLine();
                commonPasswords.add(line);
            }
            reader.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        this.dictionary = commonPasswords;

    }
}

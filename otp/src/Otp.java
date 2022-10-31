import java.io.*;
import java.util.*;

public class Otp {

    public static void main(String[] args) {

        if(args.length > 0) {

            if(args[0].equals("enc")) {
                String keyPath = args[1];
                String plaintextPath = args[2];
                String ciphertextPath = args[3];

                // Read secret key from key.txt
                String key = readTextFromFile(keyPath);
                // Read plaintext from plaintext.txt
                String plaintext = readTextFromFile(plaintextPath);

                // Call Encryption method and store ciphertext in ciphertext.txt
                String ciphertext = enc(key, plaintext);
                if(ciphertext != null) {
                    System.out.println("1. Encryption ciphertext - "+convertBinaryToString(ciphertext));
                    writeTextToFile(ciphertextPath, ciphertext);
                }
            }

            if(args[0].equals("dec")) {
                String keyPath = args[1];
                String ciphertextPath = args[2];
                String resultPath = args[3];

                // Call Decryption method and store plaintext in result.txt
                String result = dec(keyPath, ciphertextPath);
                if(result != null) {
                    System.out.println("2. Decryption plaintext - "+result);
                    writeTextToFile(resultPath, result);
                }
            }

            if(args[0].equals("keygen")) {
                String securityParameter = args[1];
                String newkeyPath = args[2];

                // Call Key Generation method and store the randomly generated key in newkey.txt
                String str = keyGen(securityParameter);
                System.out.println("3. Secret Key with "+securityParameter+" bits - " + str);
                writeTextToFile(newkeyPath, str);
            }

            if(args[0].equals("keyfreq")) {
                // Calculate distribution of keys
                Map<String, Integer> keyFrequency = keyDistribution();
                System.out.println("4. Frequency of unique keys - "+keyFrequency);
            }

            if(args[0].equals("encruntime")) {
                // Calculate avg running time of the Encryption function
                long runtime = computeRuntimeOfEnc();
                System.out.println("5. The average run time of the encryption function with security parameter = 128 is: " + runtime + " ms.");
            }
        }

    }

    /*
    method: enc
    input: key(String), plaintext(String)
    output: ciphertext(String)
    desc.: accepts key and plaintext, converts plaintext to binary, and computes ciphertext if their length is same
     */
    public static String enc(String key, String plaintext) {
        String plaintextInBinary = convertStringToBinary(plaintext);

        if (plaintextInBinary.length() == key.length()) {
            return(computeCiphertext(key, plaintextInBinary));
        } else {
            System.out.println("error in enc: length is incorrect!");
        }
        return null;
    }

    /*
    method: dec
    input: keyPath(String) - file path for key.txt, ciphertextPath(String) - file path for ciphertext.txt
    output: plaintext(String)
    desc.: reads key and ciphertext, and compute plaintext if their length is same
     */
    public static String dec(String keyPath, String ciphertextPath) {
        String key = readTextFromFile(keyPath);
        String ciphertext = readTextFromFile(ciphertextPath);
        if (ciphertext != null && ciphertext.length() == key.length()) {
            return(computePlaintext(key, ciphertext));
        } else {
            System.out.println("error in dec: length is incorrect!");
        }
        return null;
    }

    /*
    method: keyGen
    input: n(String) - security parameter from command line
    output: str(String) - new secret key of n bits
    desc.: generate a random key of n bits
     */
    public static String keyGen(String n) {
        StringBuilder str = new StringBuilder();
        int num = Integer.parseInt(n);

        for (int i = 0; i < num; i++) {
            int x = (1 + (int) (Math.random() * 100)) % 2;
            str.append(String.valueOf(x));
        }
        return str.toString();
    }

    /*
    method: keyDistribution
    input: null
    output: Map<String, Integer> - map of key frequencies
    desc.: generates 5000 4-bit keys and prints the frequency of the unique keys
     */
    public static Map<String, Integer> keyDistribution() {
        Map<String, Integer> keyFrequency = new HashMap<>();
        for (int i = 0; i < 5000; i++) {
            String key = keyGen("4");
            Integer freq = keyFrequency.getOrDefault(key, 0);
            freq++;
            keyFrequency.put(key, freq);
        }
        return keyFrequency;
    }

    /*
    method: computeRuntimeOfEnc
    input: null
    output: elapsed(long) - runtime of Encryption function in milliseconds
    desc.: computes the runtime of encryption function for security parameter = 128
     */
    public static long computeRuntimeOfEnc() {
        String key = keyGen("128");
        String plaintext = "abcdefghijklmnop";
        long start = System.currentTimeMillis();
        enc(key, plaintext);
        long elapsed = System.currentTimeMillis() - start;
        return elapsed;
    }


    /*
    method: readTextFromFile
    input: path(String) - path of the file to read from
    output: plaintext(String) - text from file
    desc.: reads the text message from file
     */
    public static String readTextFromFile(String path) {
        String text = null;
        try {
            File fis = new File(path);
            Scanner fileSc = new Scanner(fis);
            if (fileSc.hasNextLine()) {
                text = fileSc.nextLine();
            }
            fileSc.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return text;
    }

    /*
    method: writeTextToFile
    input: path(String) - path of the file to write to, text(String) - text to write in the file
    output: null
    desc.: writes the text message into file
     */
    public static void writeTextToFile(String path, String text) {
        File file = new File(path);
        FileWriter fw = null;
        try {
            fw = new FileWriter(file);
            fw.write(text);
            System.out.println("Wrote "+text+" to "+path);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fw != null) {
                    fw.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /*
    method: convertStringToBinary
    input: str(String)
    output: result(String)
    desc.: converts input string to binary
     */
    public static String convertStringToBinary(String str) {
        StringBuilder result = new StringBuilder();
        for (char c : str.toCharArray()) {
            result.append(
                    String.format("%8s", Integer.toBinaryString(c)).replaceAll(" ", "0")
            );
        }
        return result.toString();
    }

    /*
    method: computeCiphertext
    input: key(String), plaintextInBinary(String)
    output: ciphertext(String)
    desc.: computes ciphertext from key and plaintextInBinary by using one-time pad
     */
    public static String computeCiphertext(String key, String plaintextInBinary) {
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < key.length(); i++) {
            if (key.charAt(i) == plaintextInBinary.charAt(i)) {
                ciphertext.append("0");
            } else {
                ciphertext.append("1");
            }
        }
        return ciphertext.toString();
    }

    /*
    method: computePlaintext
    input: key(String), ciphertext(String)
    output: plaintext(String)
    desc.: computes plaintext from key and ciphertext by using one-time pad
     */
    public static String computePlaintext(String key, String ciphertext) {
        StringBuilder plaintextInBinary = new StringBuilder();
        for (int i = 0; i < key.length(); i++) {
            if (key.charAt(i) == ciphertext.charAt(i)) {
                plaintextInBinary.append("0");
            } else {
                plaintextInBinary.append("1");
            }
        }
        String plaintext = convertBinaryToString(plaintextInBinary.toString());
        return plaintext;

    }

    /*
    method: convertBinaryToString
    input: plaintextInBinary(String)
    output: plaintext(String)
    desc.: converts input from binary to String
     */
    public static String convertBinaryToString(String plaintextInBinary) {
        List<String> plaintextGroups = new ArrayList<>();
        int length = plaintextInBinary.length();

        for (int i = 0; i < length; i += 8) {
            plaintextGroups.add(plaintextInBinary.substring(i, Math.min(length, i + 8)));
        }

        StringBuilder plaintext = new StringBuilder();
        for (String part : plaintextGroups) {
            int val = Integer.parseInt(part, 2);
            String c = Character.toString(val);
            plaintext.append(c);
        }

        return plaintext.toString();
    }

}

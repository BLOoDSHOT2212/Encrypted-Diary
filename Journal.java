/*
 * @author NRSSI
 * Copyright 2020 N R Shyamsundar Iyanger
 * @version 6.0.1
 *
 * the crypto functions are from a suggestion in the internet
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
import java.awt.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

public class Journal {
    private JTextField textField;
    private JPasswordField passwordField;
    private String filename = "/home/" + System.getProperty("user.name") + "/Journal/" + getDate("dd-MM-yyyy");
    private final String dir = "/home/" + System.getProperty("user.name") + "/Journal/";
    private JTextArea textArea;
    private JLabel lblStatus;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(() -> {
            try {
                Journal window = new Journal();
                window.loginFrame();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private void loginFrame() {
        JFrame loginframe = new JFrame();
        loginframe.setBounds(0, 0, 350, 200);
        loginframe.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginframe.setLocationRelativeTo(null);
        loginframe.getContentPane().setLayout(null);

        JLabel lblUserName = new JLabel("User Name     :");
        lblUserName.setBounds(31, 12, 102, 14);
        loginframe.getContentPane().add(lblUserName);

        textField = new JTextField();
        textField.setBounds(125, 5, 185, 28);
        loginframe.getContentPane().add(textField);
        textField.setColumns(10);

        JLabel lblPassword = new JLabel("Password       :");
        lblPassword.setBounds(31, 56, 89, 14);
        loginframe.getContentPane().add(lblPassword);

        passwordField = new JPasswordField();
        passwordField.setBounds(125, 49, 185, 28);
        passwordField.setFocusable(true);
        loginframe.getContentPane().add(passwordField);

        JButton btnLogin = new JButton("Login");
        btnLogin.setBounds(125, 89, 80, 25);
        btnLogin.addActionListener(e -> {
            if (loginCheck() == 1) {
                createFile();
                diaryFrame();
                try {
                    decrypt("successisassured",filename,filename);
                } catch (CryptoException cryptoException) {
                    cryptoException.printStackTrace();
                }
                readFromFile(filename);
                loginframe.dispose();
            }
        });
        btnLogin.setMnemonic('\n');
        loginframe.getContentPane().add(btnLogin);

        lblStatus = new JLabel();
        lblStatus.setBounds(12, 112, 298, 37);
        lblStatus.setForeground(Color.RED);
        loginframe.getContentPane().add(lblStatus);
        loginframe.setVisible(true);

    }

    private void diaryFrame() {
        Image icon = Toolkit.getDefaultToolkit().getImage("/home/shyam/Downloads/login_nucleus.jpg");
        JFrame frame = new JFrame();
        frame.setIconImage(icon);
        frame.setBounds(0, 0, 683, 382);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(null);

        JButton btnLoad = new JButton("Load");
        btnLoad.setBounds(25, 306, 80, 24);
        btnLoad.addActionListener(e ->{
            JFileChooser fileChooser = new JFileChooser(dir);
            int returnVal = fileChooser.showOpenDialog(null);
            if(returnVal == JFileChooser.APPROVE_OPTION){
                filename = dir + fileChooser.getSelectedFile().getName();
            }
            try {
                decrypt("successisassured",filename,filename);
            } catch (CryptoException cryptoException) {
                cryptoException.printStackTrace();
            }
            textArea.setText(filename.substring(dir.length()));
            readFromFile(filename);
        });
        btnLoad.setMnemonic('l');
        frame.getContentPane().add(btnLoad);

        JButton btnSave = new JButton("Save");
        btnSave.setBounds(592, 306, 80, 24);
        btnSave.addActionListener(e -> {
            writeToFile(filename);
            try {
                encrypt("successisassured",filename,filename);
            } catch (CryptoException cryptoException) {
                cryptoException.printStackTrace();
            }
            frame.dispose();
        });
        btnSave.setMnemonic('s');
        frame.getContentPane().add(btnSave);

        JButton btnClear = new JButton("Clear");
        btnClear.setBounds(482, 307, 80, 24);
        btnClear.addActionListener(e -> textArea.setText(""));
        btnClear.setMnemonic('c');
        frame.getContentPane().add(btnClear);

        JLabel lblJournal = new JLabel("Journal -"+filename.substring(dir.length()));
        lblJournal.setBounds(25, 19, 300, 14);
        frame.getContentPane().add(lblJournal);

        textArea = new JTextArea();
        textArea.setBounds(25, 45, 629, 249);
        frame.getContentPane().add(textArea);
        textArea.setWrapStyleWord(true);
        textArea.setLineWrap(true);

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBounds(25, 45, 629, 249);
        frame.getContentPane().add(scrollPane);
        frame.setVisible(true);
    }

    private String getDate(String sample) {
        SimpleDateFormat form = new SimpleDateFormat(sample);
        Date d = new Date();
        String date = form.format(d);
        return date;
    }

    private void createFile() {
        String dir = "/home/" + System.getProperty("user.name") + "/Journal/";
        File directory = new File(dir);
        boolean isDirectory = directory.isDirectory();
        if (isDirectory) {
            File file = new File(filename);
            try {
                System.out.println("[+]Directory found creating file");
                file.createNewFile();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        } else {
            System.out.println("[-]Directory not available creating directory...");
            directory.mkdir();
            System.out.println("[+]Directory created forwarding to file creation");
            File file = new File(filename);
            try {
                file.createNewFile();
                System.out.println("[+]File created successfully...");
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private void readFromFile(String filename) {
        try {
            FileReader reader = new FileReader(filename);
            BufferedReader br = new BufferedReader(reader);
            textArea.read(br, null);
            br.close();
            textArea.requestFocus();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("\t[+]File read successfull");
    }

    private void writeToFile(String filename) {
        try {
            FileWriter writer = new FileWriter(filename);
            BufferedWriter br = new BufferedWriter(writer);
            br.append("\n\n"+getDate("hh-mm-ss")+"\n\n");
            textArea.write(br);
            br.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        System.out.println("\t[+]File write successfull");
    }

    private int loginCheck() {
        String username = textField.getText();
        String password = passwordField.getText();
        int offset = 5611;
        int user = username.hashCode() + offset;
        int pass = password.hashCode() + offset;
        int gate = 618220959;
        int key = -196275493;
        if (user == gate) {
            if (pass == key) {
                System.out.println("[+]Login successfull");
                return 1;
            } else {
                lblStatus.setText("Wrong Password");
                passwordField.setText("");
            }
        } else {
            lblStatus.setText("Wrong Username");
            passwordField.setText("");
            textField.setText("");
            passwordField.requestFocus();
            return -1;
        }
        return 0;
    }

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static void encrypt(String key, String inputFileName, String outputFileName)
            throws CryptoException {
        File inputFile = new File(inputFileName);
        File outputFile = new File(outputFileName);
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
        System.out.println("\t[+]File encrypted successfully");
    }

    public static void decrypt(String key, String inputFileName, String outputFileName)
            throws CryptoException {
        File inputFile = new File(inputFileName);
        File outputFile = new File(outputFileName);
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
        System.out.println("\t[+]File decrypted successfully");
    }

    private static void doCrypto(int cipherMode, String key, File inputFile,
                                 File outputFile) throws CryptoException {
        try {
            Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);

            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }
}
class CryptoException extends Exception {

    public CryptoException() {
    }
    public CryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}

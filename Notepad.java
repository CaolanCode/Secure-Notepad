 import org.bouncycastle.jce.provider.BouncyCastleProvider;
 import java.awt.Dimension;
 import java.awt.event.ActionEvent;
 import java.awt.event.KeyAdapter;
 import java.awt.event.KeyEvent;
 import java.io.FileNotFoundException;
 import java.io.FileReader;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
 import java.security.*;
 import java.security.spec.InvalidKeySpecException;
 import java.util.Scanner;
 import java.util.concurrent.ExecutionException;
 import javax.crypto.*;
 import javax.crypto.spec.IvParameterSpec;
 import javax.crypto.spec.PBEKeySpec;
 import javax.swing.AbstractAction;
 import javax.swing.JFileChooser;
 import javax.swing.JFrame;
 import javax.swing.JMenu;
 import javax.swing.JMenuBar;
 import javax.swing.JOptionPane;
 import javax.swing.JScrollPane;
 import javax.swing.JTextArea;
 import javax.swing.SwingUtilities;
 import javax.swing.SwingWorker;
 import javax.swing.WindowConstants;

 // Student: Caolan Mac Mahon (C00222425)
 // References:
// GeeksForGeeks: How to pad a string in Java https://www.geeksforgeeks.org/how-to-pad-a-string-in-java/
@SuppressWarnings("serial")
public class Notepad extends JFrame {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String UNTITLED = "Untitled";
    private final JFileChooser fileChooser = new JFileChooser();            // allows user to open file
    private final JTextArea textArea = new JTextArea();
    private boolean modified = false;

    public Notepad() {
        final JMenu fileMenu = new JMenu("File");

        fileMenu.add(new FileAction("New", this::newFile));         // calls FileAction method
        fileMenu.add(new FileAction("Open", this::openFile));
        fileMenu.add("Save").addActionListener(event -> saveFile());      // on action, call saveFile method
        fileMenu.addSeparator();
        fileMenu.add(new FileAction("Exit", () -> System.exit(0)));

        final JMenuBar menuBar = new JMenuBar();
        menuBar.add(fileMenu);
        setJMenuBar(menuBar);

        textArea.addKeyListener(new KeyAdapter() {      // when text area is modified
            @Override
            public void keyTyped(KeyEvent e) {
                modified = true;

            }
        });
        add(new JScrollPane(textArea));

        setTitle(UNTITLED);
        setPreferredSize(new Dimension(600, 400));
        pack();
    }

    private void newFile() {            // create a new notepad
        setTitle(UNTITLED);
        textArea.setText(null);
        modified = false;
    }

    // Opening a file can be a time-consuming task. Therefore, we open it in a
    // worker thread.
    private class FileOpener extends SwingWorker<byte[], Void> {        // executes in the background

        private final Path path;

        public FileOpener(final Path path) {
            this.path = path;
        }

        @Override
        protected byte[] doInBackground() throws IOException {
            return Files.readAllBytes(path);
        }

        @Override
        protected void done() {
            try {
                byte[] ciphertext = get();
                byte[] iv  = new byte[16];
                byte[] salt = new byte[16];
                byte[] message = new byte[ciphertext.length - 32];

                final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", "BC");

                final String passphrase = JOptionPane.showInputDialog("Enter password");
                char[] password = passphrase.toCharArray();

                System.arraycopy(ciphertext, 0, message, 0, message.length);
                System.arraycopy(ciphertext, message.length, iv,0 , iv.length);
                System.arraycopy(ciphertext, message.length + iv.length, salt, 0, salt.length);

                final Key key = factory.generateSecret(new PBEKeySpec(password,
                        salt, 1000, 256));

                String plaintext = new String(decrypt(cipher, key, iv, message));
                boolean passwordFound = false;
                String printPassword = "";

                if(checkPlaintext(plaintext)){
                    plaintext = checkForPadding(plaintext);
                    textArea.setText(plaintext);
                    setTitle(path.toString());
                    modified = false;
                } else {
                    // TODO: dictionary attack
                    try(Scanner scan = new Scanner(new FileReader("1000-common-passwords.txt"))){
                        while(scan.hasNextLine() && !passwordFound){
                            printPassword = scan.next();
                            password = printPassword.toCharArray();
                            System.out.println("Tried: " + printPassword);
                            Key keyDA = factory.generateSecret(new PBEKeySpec(password, salt, 1000, 256));
                            plaintext = new String(decrypt(cipher, keyDA, iv, message));
                            if(checkPlaintext(plaintext)) {
                                plaintext = checkForPadding(plaintext);
                                textArea.setText(plaintext);
                                setTitle(path.toString());
                                modified = false;
                                passwordFound = true;
                                System.out.println("The password is: " + printPassword);
                            }
                        }
                    } catch (FileNotFoundException e){
                        e.printStackTrace();
                    }
                }
            } catch (final InterruptedException | ExecutionException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            } catch(NoSuchProviderException e){
                e.printStackTrace();
            } catch (InvalidKeyException e){
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e){
                e.printStackTrace();
            } catch (IllegalBlockSizeException e){
                e.printStackTrace();
            }catch (BadPaddingException e){
                e.printStackTrace();
            } catch (InvalidKeySpecException e){
                e.printStackTrace();
            }
        }
    }

    private void openFile() {
        final int choice = fileChooser.showOpenDialog(this);
        if (choice == JFileChooser.APPROVE_OPTION) {
            (new FileOpener(fileChooser.getSelectedFile().toPath())).execute();
        }
    }

    // Saving a file can be a time-consuming task. Therefore, we save it in a
    // worker thread.
    private class FileSaver extends SwingWorker<Void, Void> {

        private final Path path;
        private String text;

        public FileSaver(final Path path, final String text) {
            this.path = path;
            this.text = text;
        }

        @Override
        protected Void doInBackground() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
            if(text.length() < 20){
                this.text = addPadding(text);
            }
            byte[] data = text.getBytes(StandardCharsets.UTF_8);
            final String passphrase = JOptionPane.showInputDialog("Enter password");
            char[] password = passphrase.toCharArray();
            final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", "BC");

            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            random.nextBytes(iv);

            byte[] salt = new byte[16];
            random.nextBytes(salt);

            final Key key = factory.generateSecret(new PBEKeySpec(password,
                    salt, 1000, 256));

            final byte[] ciphertext = encrypt(cipher, key, iv, data);

            byte[] allData = new byte[ciphertext.length + iv.length + salt.length];
            System.arraycopy(ciphertext, 0, allData, 0, ciphertext.length);
            System.arraycopy(iv, 0, allData, ciphertext.length, iv.length);
            System.arraycopy(salt, 0, allData, ciphertext.length + iv.length, salt.length);

            Files.write(path, allData);

            return null;
        }

        @Override
        protected void done() {
            setTitle(path.toAbsolutePath().toString());
            modified = false;
        }
    }

    private void saveFile() {
        Path path = null;
        if (getTitle().equals(UNTITLED)) {
            int choice = fileChooser.showSaveDialog(this);
            if (choice == JFileChooser.APPROVE_OPTION) {
                path = fileChooser.getSelectedFile().toPath();
            } else {
                return;
            }
        } else {
            path = Paths.get(getTitle());
        }
        (new FileSaver(path, textArea.getText())).execute();
    }

    private class FileAction extends AbstractAction {

        private Runnable action;

        public FileAction(String name, Runnable action) {
            super(name);
            this.action = action;
        }

        @Override
        public void actionPerformed(final ActionEvent e) {
            if (modified) {
                int choice = JOptionPane.showConfirmDialog(Notepad.this,
                        "The text in " + getTitle()
                                + " has changed\nDo you want to save it?",
                        "Notepad", JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.WARNING_MESSAGE);
                switch (choice) {
                    case JOptionPane.YES_OPTION:
                        saveFile();
                        action.run();
                        break;
                    case JOptionPane.NO_OPTION:
                        action.run();
                    default:
                        // cancel
                }
            } else {
                action.run();
            }
        }
    }

    private static byte[] encrypt(final Cipher cipher, final Key key,
                                  final byte[] initialisationVector, final byte[] data)
            throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, key,
                new IvParameterSpec(initialisationVector));
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(final Cipher cipher, final Key key,
                                  final byte[] initialisationVector, final byte[] data)
            throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, key,
                new IvParameterSpec(initialisationVector));
        return cipher.doFinal(data);
    }

    private boolean checkPlaintext(String plaintext){
        for(int i = 0; i < plaintext.length(); i++){
            if(plaintext.charAt(i) > 127){
                return false;
            }
        }
        return true;
    }

    private String addPadding(String plaintext){
        // add 20 spaces to the right, and then replaces the spaces with 'T' for padding
        plaintext = String.format("%" + (-20) + 's', plaintext).replace(' ', 'T');

        return plaintext;
    }

    private String checkForPadding(String plaintext){
        for(int i = plaintext.length()-1; i >= plaintext.length() - 20; i--){
            if(plaintext.charAt(i) != 'T'){
                break;
            } else {
                plaintext = plaintext.replace("T", " ");
                // trim trailing spaces
                char[] temp = plaintext.toCharArray();
                int len = plaintext.length();
                while(temp[len-1] == ' '){
                    len--;
                }
                return plaintext.substring(0, len);
            }
        }
        return plaintext;
    }

    public static void main(final String[] args) {
        SwingUtilities.invokeLater(() -> {
            final Notepad notepad = new Notepad();
            notepad.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            notepad.setVisible(true);
        });
    }
}
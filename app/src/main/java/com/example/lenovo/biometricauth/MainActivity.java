package com.example.lenovo.biometricauth;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;

public class MainActivity extends AppCompatActivity {

    public static final String KEY = "MY_KEY";
    private Cipher cipher;
    private KeyGenerator keyGenerator;
    private KeyStore keyStore;
    private TextView textView;
    private FingerprintManager.CryptoObject cryptoObject;
    private FingerprintManager fingerprintManagerCompat;
    private KeyguardManager keyguardManager;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            fingerprintManagerCompat = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);


            if (!fingerprintManagerCompat.isHardwareDetected()) {
                Toast.makeText(MainActivity.this, "Your device is not supported for biometric authentication", Toast.LENGTH_LONG).show();
            }

            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(MainActivity.this, "Please enable fingerprint permission", Toast.LENGTH_SHORT).show();
            }

            if (!fingerprintManagerCompat.hasEnrolledFingerprints()) {
                Toast.makeText(MainActivity.this, "No fingerprint registered. Please enroll atleast one fingerprint", Toast.LENGTH_SHORT).show();
            }

            //if (keyguardManager.isKeyguardSecure()) {
            //    Toast.makeText(MainActivity.this, "Please enable lockscreen security in your device", Toast.LENGTH_SHORT).show();
            //}
            else {
                generateKey();
                if (initCipher()) {
                    cryptoObject = new FingerprintManager.CryptoObject(cipher);
                    FingerprintHandler helper = new FingerprintHandler(this);
                    helper.startAuth(fingerprintManagerCompat, cryptoObject);
                }
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            keyStore.load(null);

            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            keyGenerator.generateKey();
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | IOException exec) {
            exec.printStackTrace();
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean initCipher() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        }
        return false;
    }

    private class FingerprintException extends Exception{
        public FingerprintException(Exception e){
            super(e);
        }
    }
}


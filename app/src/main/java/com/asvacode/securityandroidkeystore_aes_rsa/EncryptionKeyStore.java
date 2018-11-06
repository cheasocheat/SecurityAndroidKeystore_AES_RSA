package com.asvacode.securityandroidkeystore_aes_rsa;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.asvacode.securityandroidkeystore_aes_rsa.BuildConfig;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.x500.X500Principal;

/**
 * Created by cheasocheat On 10/24/18.
 */
public class EncryptionKeyStore {

    private static final String CIPHER_API_18 = "RSA/ECB/PKCS1Padding";
    private static final String CIPHER_API_23 = "AES/GCM/NoPadding";
    //KeyProperties.KEY_ALGORITHM_AES // + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
    private static final String CIPHER = (isApi23()) ? CIPHER_API_23 : CIPHER_API_18;
    private static final String TYPE_RSA = "RSA";

    private byte[] iv;

    public EncryptionKeyStore() {

    }


    /**
     * PrepareChiper for encryption method
     *
     * @return
     */
    private Cipher prepareCipher() {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        return cipher;
    }

    /**
     * PrepareKeyStore to get cryptographic from Keystore
     *
     * @return
     */
    public KeyStore prepareKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance(BuildConfig.KEYSTORE_PROVIDER_NAME);
            ks.load(null);
            return ks;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * GEt Secret Key
     *
     * @param alias
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableEntryException
     * @throws KeyStoreException
     */
    private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
            UnrecoverableEntryException, KeyStoreException {
        return ((KeyStore.SecretKeyEntry) this.prepareKeyStore().getEntry(alias, null)).getSecretKey();
    }

    /**
     * Encrypt text using cipher
     *
     * @param alias
     * @param textToEncrypt
     * @return
     */
    public byte[] encryptText(final String alias, final String textToEncrypt) {
        final KeyStore ks = prepareKeyStore();
        final Cipher cipher = prepareCipher();

        try {
            final Key key;
            if (isApi23()) {
                key = ks.getKey(alias, null);
            } else {
                final KeyStore.PrivateKeyEntry privateKeyEntry;
                try {
                    privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, null);
                    key = privateKeyEntry.getCertificate().getPublicKey();
                } catch (UnrecoverableEntryException e) {
                    throw new RuntimeException("key for encryption is invalid", e);
                }
            }

            cipher.init(Cipher.ENCRYPT_MODE, key);
            iv = cipher.getIV();
            return cipher.doFinal(textToEncrypt.getBytes("UTF-8"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Used to decrypt text from cipher
     *
     * @param alias
     * @param encryptedData
     * @param encryptionIv
     * @return
     */
    @TargetApi(Build.VERSION_CODES.KITKAT)
    public String decryptData(final String alias, final byte[] encryptedData, final byte[] encryptionIv) {
        final Cipher cipher = prepareCipher();
        final KeyStore ks = prepareKeyStore();

        try {
            final Key key = ks.getKey(alias, null);
            //Check whether encryptionIv is not null
            if (encryptionIv != null) {
                final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            return new String(cipher.doFinal(encryptedData), "UTF-8");
        } catch (InvalidKeyException e) {
            throw new RuntimeException("key is invalid.");
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | BadPaddingException
                | KeyStoreException | IllegalBlockSizeException | InvalidAlgorithmParameterException |
                UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean isApi23() {
        return (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M);
    }

    /**
     * Gernate KeyInKeyStore Android System
     *
     * @param context
     * @param alias
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public void generateKeyInKeyStore(Context context, final String alias) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                final KeyGenerator keyGenerator;
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, BuildConfig.KEYSTORE_PROVIDER_NAME);

                final KeyGenParameterSpec keySpec;

               /* keySpec = new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(false)
                        .build();
                */
                keySpec = new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();

                try {
                    keyGenerator.init(keySpec);
                } catch (InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }

                keyGenerator.generateKey();
            } else {
                Calendar start = new GregorianCalendar();
                Calendar end = new GregorianCalendar();
                end.add(Calendar.YEAR, 25);

                KeyPairGeneratorSpec spec =
                        new KeyPairGeneratorSpec.Builder(context)
                                .setAlias(alias)
                                .setSubject(new X500Principal("CN=" + alias))
                                .setSerialNumber(BigInteger.valueOf(1337))
                                .setStartDate(start.getTime())
                                .setEndDate(end.getTime())
                                .build();

                final KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(TYPE_RSA, BuildConfig.KEYSTORE_PROVIDER_NAME);
                kpGenerator.initialize(spec);
                kpGenerator.generateKeyPair();
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Provide iv
     *
     * @return
     */
    public byte[] getIv() {
        return iv;
    }
}

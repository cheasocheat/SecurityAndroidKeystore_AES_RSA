package com.asvacode.securityandroidkeystore_aes_rsa

import android.annotation.SuppressLint
import android.os.Build
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    private var encryptionKeyStore: EncryptionKeyStore? = null
    private var encryptedStringData: String? = null
    private var encryptedStringIv: String? = null

    @SuppressLint("LogNotTimber", "SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        //Init Keystore
        encryptionKeyStore = EncryptionKeyStore()

        //Generate Key In KeyStore
        val prefManager = PreferenceManager(this)
        val isGenerated: Boolean = prefManager.getValue(PreferenceManager.KEYSTORE_GENERATED, false) as Boolean
        if (BuildConfig.SECRET_ALIAS.isNotEmpty() && !isGenerated) {
            encryptionKeyStore!!.generateKeyInKeyStore(this, BuildConfig.SECRET_ALIAS)
            Log.d("AsvaTag", "KeyStore was generated successfully!")
            prefManager.setValue(PreferenceManager.KEYSTORE_GENERATED, true)
        }



        tvApplicationId.text = "Application Id = ${BuildConfig.APPLICATION_ID}"
        tvSecret.text = "Secret = ${BuildConfig.KEYSTORE_PROVIDER_NAME}"

        btnEncrypt.setOnClickListener {
            if(edtData.text.trim().toString().isEmpty()){
                Toast.makeText(this,"Please input any data to encrypt!", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val encryptedData = encryptionKeyStore!!.encryptText(BuildConfig.SECRET_ALIAS, edtData.text.toString())
            val encryptedIv = encryptionKeyStore!!.iv
            encryptedStringData = Base64.encodeToString(encryptedData, Base64.DEFAULT)
            if (encryptedIv != null) {
                encryptedStringIv = Base64.encodeToString(encryptedIv, Base64.DEFAULT)
            }
            tvResult.text = "Encrypted Data : $encryptedStringData \n\nEncrypted IV = $encryptedStringIv"
        }

        btnDecrypt.setOnClickListener {
            if(encryptedStringData == null){
                Toast.makeText(this,"No encrypted byte array were found! Please click on encrypt first!", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            var decrypted: String = ""
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val cipherCred = Base64.decode(encryptedStringData, Base64.DEFAULT)
                val cipherIv = Base64.decode(encryptedStringIv, Base64.DEFAULT)
                if (cipherCred.isNotEmpty() && cipherIv.isNotEmpty()) {
                    decrypted = encryptionKeyStore!!.decryptData(BuildConfig.SECRET_ALIAS, cipherCred, cipherIv)
                }
            } else {
                val cipherCred = Base64.decode(encryptedStringData, Base64.DEFAULT)
                if (cipherCred.isNotEmpty()) {
                    decrypted = encryptionKeyStore!!.decryptData(BuildConfig.SECRET_ALIAS, cipherCred, null)
                }
            }
            tvResult.text = "Decrypted Data : $decrypted"
        }
    }

}

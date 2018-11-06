package com.asvacode.securityandroidkeystore_aes_rsa

import android.content.Context

/**
 * Created by: cheasocheat
 * Date: 11/5/18 11:02 PM
 */


class PreferenceManager constructor(context: Context) {

    companion object {
        const val KEYSTORE_GENERATED = "keystore_generated"
    }

    private var prefs = PreferenceHelper.instance(context)

    fun setValue(key: String, value: Any) {
        prefs[key] = value
    }

    fun getValue(key: String, default: Any?): Any? {
        return when (default) {
            is String? -> {
                val data: String? = prefs[key, default]
                data
            }
            is Int? -> {
                val data: Int? = prefs[key, default]
                data
            }
            is Boolean? -> {
                val data: Boolean? = prefs[key, default]
                data
            }
            is Float -> {
                val data: Float? = prefs[key, default]
                data
            }
            is Long -> {
                val data: Long? = prefs[key, default]
                data
            }
            else -> {
                throw UnsupportedOperationException("Not yet implemented")
            }
        }
    }
}
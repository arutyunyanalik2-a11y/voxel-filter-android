package com.filter

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class VpnFilterService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        init {
            // Загружаем нашу скомпилированную Rust-библиотеку
            System.loadLibrary("core_rust")
        }
    }

    // Объявляем нативную функцию из Rust, которая проверяет домен
    external fun checkDomainNative(domain: String): Boolean

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            isRunning = true
            startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        val builder = Builder()
            .setSession("System Filter 18+")
            .addAddress("10.0.0.2", 24)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)

        vpnInterface = builder.establish()
        
        // Запускаем поток обработки пакетов в фоне
        Thread {
            runVpnLoop()
        }.start()
    }

    private fun runVpnLoop() {
        val descriptor = vpnInterface ?: return
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767)

        try {
            while (isRunning) {
                val length = inputStream.read(buffer.array())
                if (length > 0) {
                    // Здесь в будущем можно детально парсить DNS/IP пакеты, 
                    // а пока движок готов принимать запросы.
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        vpnInterface?.close()
        vpnInterface = null
    }
}
package com.filter

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class VpnFilterService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        init {
            System.loadLibrary("core_rust")
        }
    }

    external fun checkDomainNative(domain: String): Boolean

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            isRunning = true
            startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        try {
            val builder = Builder()
                .setSession("System Filter 18+")
                .addAddress("10.0.0.2", 24)
                .addDnsServer("8.8.8.8")
                // Перенаправляем только DNS (порт 53), чтобы система стабильно держала туннель
                .addRoute("8.8.8.8", 32) 

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e("VpnFilter", "Ошибка: builder.establish() вернул null. VPN не запущен.")
                return
            }

            Log.i("VpnFilter", "VPN успешно активирован!")
            Thread {
                runVpnLoop()
            }.start()
        } catch (e: Exception) {
            Log.e("VpnFilter", "Исключение при старте VPN: ${e.message}")
        }
    }

    private fun runVpnLoop() {
        val descriptor = vpnInterface ?: return
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val outputStream = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767)

        try {
            while (isRunning) {
                val length = inputStream.read(buffer.array())
                if (length > 0) {
                    val packet = buffer.array()
                    
                    // Перехватываем и проверяем DNS-запросы
                    if (isDnsPacket(packet, length)) {
                        val domain = extractDomainFromDns(packet, length)
                        if (domain != null && checkDomainNative(domain)) {
                            Log.d("VpnFilter", "Заблокирован домен: $domain")
                            buffer.clear()
                            continue // Блокируем пакет
                        }
                    }

                    outputStream.write(packet, 0, length)
                    buffer.clear()
                }
            }
        } catch (e: Exception) {
            Log.e("VpnFilter", "Ошибка в loop: ${e.message}")
        }
    }

    private fun isDnsPacket(packet: ByteArray, length: Int): Boolean {
        if (length < 28) return false
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return false // UDP

        val destinationPort = ((packet[ipHeaderLength + 2].toInt() and 0xFF) shl 8) or
                              (packet[ipHeaderLength + 3].toInt() and 0xFF)
        return destinationPort == 53
    }

    private fun extractDomainFromDns(packet: ByteArray, length: Int): String? {
        try {
            val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
            var dnsOffset = ipHeaderLength + 8 + 12
            
            val domainBuilder = StringBuilder()
            while (dnsOffset < length) {
                val labelLength = packet[dnsOffset].toInt() and 0xFF
                if (labelLength == 0) break
                
                if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
                for (i in 0 until labelLength) {
                    dnsOffset++
                    domainBuilder.append(packet[dnsOffset].toInt().toChar())
                }
                dnsOffset++
            }
            return if (domainBuilder.isNotEmpty()) domainBuilder.toString() else null
        } catch (e: Exception) {
            return null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        vpnInterface?.close()
        vpnInterface = null
    }
}
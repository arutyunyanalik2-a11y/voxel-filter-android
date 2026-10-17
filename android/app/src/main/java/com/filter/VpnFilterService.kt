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
        val builder = Builder()
            .setSession("System Filter 18+")
            .addAddress("10.0.0.2", 24)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)

        vpnInterface = builder.establish()
        
        Thread {
            runVpnLoop()
        }.start()
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
                    
                    var blocked = false
                    // 1. Проверяем DNS (порт 53)
                    if (isDnsPacket(packet, length)) {
                        val domain = extractDomainFromDns(packet, length)
                        if (domain != null && checkDomainNative(domain)) {
                            Log.d("VpnFilter", "Заблокирован по DNS: $domain")
                            blocked = true
                        }
                    } 
                    // 2. Проверяем HTTPS / TLS SNI (порт 443)
                    else if (isTlsClientHello(packet, length)) {
                        val domain = extractTlsSni(packet, length)
                        if (domain != null && checkDomainNative(domain)) {
                            Log.d("VpnFilter", "Заблокирован по SNI (HTTPS): $domain")
                            blocked = true
                        }
                    }

                    if (blocked) {
                        buffer.clear()
                        continue // Сбрасываем пакет (блокируем)
                    }

                    // Пропускаем чистый трафик дальше
                    outputStream.write(packet, 0, length)
                    buffer.clear()
                }
            }
        } catch (e: Exception) {
            Log.e("VpnFilter", "Ошибка в loop: ${e.message}")
        }
    }

    private fun isTlsClientHello(packet: ByteArray, length: Int): Boolean {
        if (length < 40) return false
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 6) return false // TCP = 6

        val tcpHeaderLength = ((packet[ipHeaderLength + 12].toInt() and 0xF0) shr 4) * 4
        val payloadOffset = ipHeaderLength + tcpHeaderLength
        if (length <= payloadOffset + 5) return false

        val contentType = packet[payloadOffset].toInt() and 0xFF
        val handshakeType = packet[payloadOffset + 5].toInt() and 0xFF
        return contentType == 22 && handshakeType == 1
    }

    private fun extractTlsSni(packet: ByteArray, length: Int): String? {
        try {
            val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
            val tcpHeaderLength = ((packet[ipHeaderLength + 12].toInt() and 0xF0) shr 4) * 4
            var offset = ipHeaderLength + tcpHeaderLength + 5 + 4 + 2 + 32 + 1
            
            val sessionIDLength = packet[offset].toInt() and 0xFF
            offset += 1 + sessionIDLength
            
            val cipherSuitesLength = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
            offset += 2 + cipherSuitesLength
            
            val compressionLength = packet[offset].toInt() and 0xFF
            offset += 1 + compressionLength
            
            offset += 2
            
            while (offset < length - 4) {
                val extType = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                val extLen = ((packet[offset + 2].toInt() and 0xFF) shl 8) or (packet[offset + 3].toInt() and 0xFF)
                offset += 4
                
                if (extType == 0) { // SNI
                    val serverNameListLen = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                    val serverNameType = packet[offset + 2].toInt() and 0xFF
                    if (serverNameType == 0) {
                        val hostNameLen = ((packet[offset + 3].toInt() and 0xFF) shl 8) or (packet[offset + 4].toInt() and 0xFF)
                        val hostBytes = packet.copyOfRange(offset + 5, offset + 5 + hostNameLen)
                        return String(hostBytes, Charsets.UTF_8)
                    }
                }
                offset += extLen
            }
        } catch (e: Exception) {}
        return null
    }

    private fun isDnsPacket(packet: ByteArray, length: Int): Boolean {
        if (length < 28) return false
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return false

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
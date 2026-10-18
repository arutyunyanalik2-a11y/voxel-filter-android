package com.filter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors

class VpnFilterService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false
    private val executor = Executors.newCachedThreadPool()

    companion object {
        init {
            System.loadLibrary("core_rust")
        }
        private const val CHANNEL_ID = "VpnFilterChannel"
        private const val NOTIFICATION_ID = 1
    }

    external fun checkDomainNative(domain: String): Boolean

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "STOP_VPN") {
            stopVpn()
            return START_NOT_STICKY
        }

        if (!isRunning) {
            isRunning = true
            startForegroundServiceWithNotification()
            startVpn()
        }
        return START_STICKY
    }

    private fun startForegroundServiceWithNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Voxel Rivo Protection",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Voxel Rivo Filter")
            .setContentText("Защита 18+ активна")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun startVpn() {
        try {
            val builder = Builder()
                .setSession("System Filter 18+")
                .addAddress("10.0.0.2", 24)
                .addDnsServer("8.8.8.8")
                .addRoute("8.8.8.8", 32)

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e("VpnFilter", "builder.establish() returned null")
                return
            }

            Log.i("VpnFilter", "VPN Tunnel active")
            Thread { runVpnLoop() }.start()
        } catch (e: Exception) {
            Log.e("VpnFilter", "Error starting VPN: ${e.message}")
        }
    }

    private fun runVpnLoop() {
        val descriptor = vpnInterface ?: return
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val outputStream = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(32767)

        try {
            while (isRunning) {
                val length = inputStream.read(buffer)
                if (length > 0) {
                    val packet = buffer.copyOf(length)
                    if (isDnsPacket(packet, length)) {
                        val domain = extractDomainFromDns(packet, length)
                        if (domain != null && checkDomainNative(domain)) {
                            Log.d("VpnFilter", "Blocked 18+ domain: $domain")
                            continue // Блокируем: не отвечаем на запрос
                        }

                        // Если домен разрешен — проксируем запрос на реальный 8.8.8.8 в отдельном потоке
                        executor.submit {
                            proxyDnsQuery(packet, length, outputStream)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e("VpnFilter", "VPN loop error: ${e.message}")
            }
        }
    }

    private fun proxyDnsQuery(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            val udpHeaderLen = 8
            val dnsPayloadOffset = ipHeaderLen + udpHeaderLen
            val dnsQueryLength = length - dnsPayloadOffset

            if (dnsQueryLength <= 0) return

            val dnsQueryBytes = ByteArray(dnsQueryLength)
            System.arraycopy(packet, dnsPayloadOffset, dnsQueryBytes, 0, dnsQueryLength)

            // Отправляем через реальный сокет на 8.8.8.8:53
            val socket = DatagramSocket()
            protect(socket) // Защищаем сокет, чтобы он не попадал в петлю VPN
            
            val dnsAddress = InetAddress.getByName("8.8.8.8")
            val sendPacket = DatagramPacket(dnsQueryBytes, dnsQueryBytes.size, dnsAddress, 53)
            socket.send(sendPacket)

            val receiveBuffer = ByteArray(1024)
            val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
            socket.soTimeout = 3000 // таймаут 3 секунды
            socket.receive(receivePacket)
            socket.close()

            val dnsResponsePayload = receivePacket.data.copyOf(receivePacket.length)

            // Собираем обратно IP+UDP пакет с ответом DNS и отправляем в туннель
            val responsePacket = buildDnsResponsePacket(packet, dnsResponsePayload)
            synchronized(outputStream) {
                outputStream.write(responsePacket)
            }
        } catch (e: Exception) {
            Log.e("VpnFilter", "DNS Proxy error: ${e.message}")
        }
    }

    private fun buildDnsResponsePacket(originalIpPacket: ByteArray, dnsResponsePayload: ByteArray): ByteArray {
        val ipHeaderLen = (originalIpPacket[0].toInt() and 0x0F) * 4
        val totalLength = ipHeaderLen + 8 + dnsResponsePayload.size
        val packet = ByteArray(totalLength)

        // Копируем IP заголовок с заменой Source и Destination местами
        System.arraycopy(originalIpPacket, 0, packet, 0, ipHeaderLen)
        packet[2] = (totalLength shr 8).toByte()
        packet[3] = (totalLength and 0xFF).toByte()

        // Swap IP addresses
        System.arraycopy(originalIpPacket, 16, packet, 12, 4) // Src = old Dst
        System.arraycopy(originalIpPacket, 12, packet, 16, 4) // Dst = old Src

        // UDP Header
        val udpSrcOffset = ipHeaderLen
        val udpDstOffset = ipHeaderLen + 2
        val udpLenOffset = ipHeaderLen + 4
        val udpChkOffset = ipHeaderLen + 6

        packet[udpSrcOffset] = originalIpPacket[udpDstOffset]
        packet[udpSrcOffset + 1] = originalIpPacket[udpDstOffset + 1]
        packet[udpDstOffset] = originalIpPacket[udpSrcOffset]
        packet[udpDstOffset + 1] = originalIpPacket[udpSrcOffset + 1]

        val udpLen = 8 + dnsResponsePayload.size
        packet[udpLenOffset] = (udpLen shr 8).toByte()
        packet[udpLenOffset + 1] = (udpLen and 0xFF).toByte()
        packet[udpChkOffset] = 0
        packet[udpChkOffset + 1] = 0

        // UDP Payload (DNS Response)
        System.arraycopy(dnsResponsePayload, 0, packet, ipHeaderLen + 8, dnsResponsePayload.size)

        return packet
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

    private fun stopVpn() {
        isRunning = false
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("VpnFilter", "Error closing interface: ${e.message}")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        executor.shutdownNow()
        super.onDestroy()
    }
}
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
    private val executor = Executors.newFixedThreadPool(16)
    private val writeLock = Any()

    companion object {
        init {
            System.loadLibrary("core_rust")
        }
        private const val TAG = "VpnFilter"
        private const val CHANNEL_ID = "VoxelRivoChannel"
        private const val NOTIFICATION_ID = 1
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val UPSTREAM_DNS = "8.8.8.8"
    }

    external fun checkDomainNative(domain: String): Boolean

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action}")
        if (intent?.action == "STOP_VPN") {
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
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
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
            // В туннель попадает только трафик к нашему DNS (10.0.0.2).
            // Весь остальной трафик идёт напрямую, мимо VPN.
            val builder = Builder()
                .setSession("Voxel Rivo Filter")
                .addAddress(VPN_ADDRESS, 24)
                .addDnsServer(VPN_ADDRESS)
                .addRoute(VPN_ADDRESS, 32)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "builder.establish() returned null (нет разрешения VPN?)")
                isRunning = false
                return
            }

            setUnderlyingNetworks(null)

            Log.i(TAG, "DNS VPN Tunnel active")
            Thread { runVpnLoop() }.start()
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN: ${e.message}", e)
            isRunning = false
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
                if (length < 0) break
                if (length == 0) continue

                val packet = buffer.copyOf(length)

                // Всё, что не является UDP DNS-запросом, отбрасываем
                if (!isDnsPacket(packet, length)) continue

                val domain = extractDomainFromDns(packet, length)
                Log.i(TAG, "DNS query: $domain")

                if (domain != null && checkDomainNative(domain.lowercase())) {
                    Log.i(TAG, "BLOCKED 18+ domain: $domain")
                    // Отвечаем NXDOMAIN, чтобы приложение сразу получило ошибку, а не ждало таймаут
                    val nx = buildNxDomainPayload(packet, length)
                    if (nx != null) {
                        val response = buildDnsResponsePacket(packet, nx)
                        synchronized(writeLock) { outputStream.write(response) }
                    }
                    continue
                }

                executor.submit { proxyDnsQuery(packet, length, outputStream) }
            }
        } catch (e: Exception) {
            if (isRunning) Log.e(TAG, "VPN loop error: ${e.message}", e)
        }
    }

    private fun proxyDnsQuery(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            val dnsPayloadOffset = ipHeaderLen + 8
            val dnsQueryLength = length - dnsPayloadOffset
            if (dnsQueryLength <= 0) return

            val dnsQueryBytes = packet.copyOfRange(dnsPayloadOffset, dnsPayloadOffset + dnsQueryLength)

            DatagramSocket().use { socket ->
                protect(socket) // чтобы запрос к 8.8.8.8 не зациклился в наш же туннель
                socket.soTimeout = 3000

                val upstream = InetAddress.getByName(UPSTREAM_DNS)
                socket.send(DatagramPacket(dnsQueryBytes, dnsQueryBytes.size, upstream, 53))

                val receiveBuffer = ByteArray(4096)
                val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
                socket.receive(receivePacket)

                val dnsResponse = receivePacket.data.copyOf(receivePacket.length)
                val responsePacket = buildDnsResponsePacket(packet, dnsResponse)
                synchronized(writeLock) { outputStream.write(responsePacket) }
            }
        } catch (e: Exception) {
            Log.e(TAG, "DNS Proxy error: ${e.message}")
        }
    }

    /** Формирует DNS-ответ NXDOMAIN на основе исходного запроса. */
    private fun buildNxDomainPayload(packet: ByteArray, length: Int): ByteArray? {
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val dnsStart = ipHeaderLen + 8
        if (length < dnsStart + 12) return null

        // Находим конец секции Question
        var pos = dnsStart + 12
        while (pos < length && packet[pos].toInt() != 0) {
            pos += (packet[pos].toInt() and 0xFF) + 1
        }
        pos += 1 + 4 // нулевой байт + QTYPE + QCLASS
        if (pos > length) return null

        val payload = packet.copyOfRange(dnsStart, pos)
        payload[2] = 0x81.toByte() // QR=1 (ответ), RD=1
        payload[3] = 0x83.toByte() // RA=1, RCODE=3 (NXDOMAIN)
        payload[6] = 0; payload[7] = 0   // ANCOUNT = 0
        payload[8] = 0; payload[9] = 0   // NSCOUNT = 0
        payload[10] = 0; payload[11] = 0 // ARCOUNT = 0
        return payload
    }

    private fun buildDnsResponsePacket(originalIpPacket: ByteArray, dnsResponsePayload: ByteArray): ByteArray {
        val ipHeaderLen = (originalIpPacket[0].toInt() and 0x0F) * 4
        val totalLength = ipHeaderLen + 8 + dnsResponsePayload.size
        val packet = ByteArray(totalLength)

        // IP-заголовок: копируем, меняем длину и меняем местами src/dst
        System.arraycopy(originalIpPacket, 0, packet, 0, ipHeaderLen)
        packet[2] = (totalLength shr 8).toByte()
        packet[3] = (totalLength and 0xFF).toByte()
        System.arraycopy(originalIpPacket, 16, packet, 12, 4)
        System.arraycopy(originalIpPacket, 12, packet, 16, 4)

        // ГЛАВНОЕ ИСПРАВЛЕНИЕ: пересчитываем контрольную сумму IP-заголовка
        packet[10] = 0
        packet[11] = 0
        val checksum = ipChecksum(packet, ipHeaderLen)
        packet[10] = (checksum shr 8).toByte()
        packet[11] = (checksum and 0xFF).toByte()

        // UDP: меняем местами порты
        val udp = ipHeaderLen
        packet[udp] = originalIpPacket[udp + 2]
        packet[udp + 1] = originalIpPacket[udp + 3]
        packet[udp + 2] = originalIpPacket[udp]
        packet[udp + 3] = originalIpPacket[udp + 1]

        val udpLen = 8 + dnsResponsePayload.size
        packet[udp + 4] = (udpLen shr 8).toByte()
        packet[udp + 5] = (udpLen and 0xFF).toByte()
        packet[udp + 6] = 0 // для IPv4 UDP-checksum = 0 допустим
        packet[udp + 7] = 0

        System.arraycopy(dnsResponsePayload, 0, packet, ipHeaderLen + 8, dnsResponsePayload.size)
        return packet
    }

    private fun ipChecksum(buf: ByteArray, headerLen: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLen) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum shr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun isDnsPacket(packet: ByteArray, length: Int): Boolean {
        if (length < 28) return false
        if (((packet[0].toInt() shr 4) and 0x0F) != 4) return false // только IPv4
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (length < ipHeaderLength + 8) return false
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return false // только UDP

        val destinationPort = ((packet[ipHeaderLength + 2].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLength + 3].toInt() and 0xFF)
        return destinationPort == 53
    }

    private fun extractDomainFromDns(packet: ByteArray, length: Int): String? {
        try {
            val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
            var dnsOffset = ipHeaderLength + 8 + 12

            val sb = StringBuilder()
            while (dnsOffset < length) {
                val labelLength = packet[dnsOffset].toInt() and 0xFF
                if (labelLength == 0) break
                if (dnsOffset + labelLength >= length) return null

                if (sb.isNotEmpty()) sb.append('.')
                for (i in 0 until labelLength) {
                    dnsOffset++
                    sb.append((packet[dnsOffset].toInt() and 0xFF).toChar())
                }
                dnsOffset++
            }
            return if (sb.isNotEmpty()) sb.toString() else null
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
            Log.e(TAG, "Error closing interface: ${e.message}")
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
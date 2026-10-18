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
import kotlin.concurrent.thread

class VpnFilterService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false
    private var dnsSocket: DatagramSocket? = null

    companion object {
        init {
            System.loadLibrary("core_rust")
        }
        private const val CHANNEL_ID = "VpnFilterChannel"
        private const val NOTIFICATION_ID = 1
    }

    external fun checkDomainNative(domain: String): Boolean

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
                .addDnsServer("10.0.0.2") // Направляем DNS на наш локальный туннель
                .addRoute("10.0.0.2", 32)

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e("VpnFilter", "builder.establish() returned null")
                return
            }

            Log.i("VpnFilter", "VPN Tunnel active")
            
            // Запускаем локальный DNS прокси-сервер на внешнем сокете
            thread { startDnsProxyServer() }
            // Читаем туннель
            thread { runVpnReadLoop() }
            
        } catch (e: Exception) {
            Log.e("VpnFilter", "Error starting VPN: ${e.message}")
        }
    }

    private fun startDnsProxyServer() {
        try {
            val socket = DatagramSocket()
            protect(socket) // Важно: защищаем сокет от попадания в VPN петлю
            dnsSocket = socket

            val upstreamDns = InetAddress.getByName("8.8.8.8")
            val buffer = ByteArray(2048)

            while (isRunning) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (e: Exception) {
                    break
                }

                val domain = extractDomainFromDnsPayload(packet.data, packet.length)
                
                if (domain != null && checkDomainNative(domain)) {
                    Log.d("VpnFilter", "BLOCKED: $domain")
                    // Блокируем — не отправляем дальше на 8.8.8.8
                    continue
                }

                // Перенаправляем разрешенный запрос на Google DNS
                val forwardPacket = DatagramPacket(packet.data, packet.length, upstreamDns, 53)
                socket.send(forwardPacket)
            }
        } catch (e: Exception) {
            Log.e("VpnFilter", "Proxy server error: ${e.message}")
        }
    }

    private fun runVpnReadLoop() {
        val descriptor = vpnInterface ?: return
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(32767)

        try {
            while (isRunning) {
                // Просто вычитываем пакеты из туннеля, чтобы система не блокировала трафик
                val length = inputStream.read(buffer)
                if (length <= 0) break
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e("VpnFilter", "VPN read loop error: ${e.message}")
            }
        }
    }

    private fun extractDomainFromDnsPayload(payload: ByteArray, length: Int): String? {
        try {
            var dnsOffset = 12 // Пропускаем DNS Header (12 байт)
            val domainBuilder = StringBuilder()
            
            while (dnsOffset < length) {
                val labelLength = payload[dnsOffset].toInt() and 0xFF
                if (labelLength == 0) break
                
                if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
                for (i in 0 until labelLength) {
                    dnsOffset++
                    domainBuilder.append(payload[dnsOffset].toInt().toChar())
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
            dnsSocket?.close()
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
        super.onDestroy()
    }
}
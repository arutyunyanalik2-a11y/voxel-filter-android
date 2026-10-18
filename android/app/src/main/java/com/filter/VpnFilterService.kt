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

class VpnFilterService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false

    companion object {
        init {
            System.loadLibrary("core_rust")
        }
        private const val CHANNEL_ID = "VoxelRivoChannel"
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
                .setSession("Voxel Rivo Filter")
                .addAddress("10.0.0.2", 24)
                .addDnsServer("8.8.8.8") // Используем публичный DNS Google напрямую
                .addRoute("0.0.0.0", 0)   // Перенаправляем весь трафик для контроля

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e("VpnFilter", "builder.establish() returned null")
                return
            }

            Log.i("VpnFilter", "VPN Tunnel active successfully")
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
                    
                    // Проверяем, является ли пакет DNS-запросом (порт 53)
                    if (isDnsPacket(packet, length)) {
                        val domain = extractDomainFromDns(packet, length)
                        if (domain != null && checkDomainNative(domain)) {
                            Log.d("VpnFilter", "BLOCKED 18+ domain: $domain")
                            // Блокируем пакет: не пишем его в outputStream, запросы обрываются
                            continue
                        }
                    }

                    // Весь остальной трафик и разрешенные DNS-запросы пропускаем дальше
                    outputStream.write(packet, 0, length)
                }
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e("VpnFilter", "VPN loop error: ${e.message}")
            }
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
            var dnsOffset = ipHeaderLength + 8 + 12 // Пропускаем IP, UDP и заголовок DNS
            
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
        super.onDestroy()
    }
}
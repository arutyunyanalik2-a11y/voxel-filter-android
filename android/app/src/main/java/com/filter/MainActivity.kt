package com.filter

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private var isVpnActive = false
    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button
    private lateinit var mainLayout: LinearLayout

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        mainLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 128, 64, 128)
            gravity = android.view.Gravity.CENTER
            
            val gradient = GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                intArrayOf(
                    Color.rgb(17, 0, 255),
                    Color.rgb(255, 157, 0)
                )
            )
            background = gradient
        }

        val titleText = TextView(this).apply {
            text = "Voxel Rivo Filter"
            textSize = 28f
            setTextColor(Color.WHITE)
            setTypeface(null, android.graphics.Typeface.BOLD)
            gravity = android.view.Gravity.CENTER
            setPadding(0, 0, 0, 16)
        }

        statusText = TextView(this).apply {
            text = "Защита отключена"
            textSize = 18f
            setTextColor(Color.argb(220, 255, 255, 255))
            gravity = android.view.Gravity.CENTER
            setPadding(0, 0, 0, 64)
        }

        toggleButton = Button(this).apply {
            text = "Включить защиту"
            textSize = 18f
            setTextColor(Color.rgb(17, 0, 255))
            
            val buttonBg = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = 48f
            }
            background = buttonBg
            setPadding(48, 24, 48, 24)

            setOnClickListener {
                if (isVpnActive) {
                    stopVpnService()
                } else {
                    prepareAndStartVpn()
                }
            }
        }

        mainLayout.addView(titleText)
        mainLayout.addView(statusText)
        mainLayout.addView(toggleButton)

        setContentView(mainLayout)
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPrepareLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, VpnFilterService::class.java)
        startService(intent)
        isVpnActive = true
        updateUiState()
    }

    private fun stopVpnService() {
        val intent = Intent(this, VpnFilterService::class.java).apply {
            action = "STOP_VPN"
        }
        startService(intent)
        isVpnActive = false
        updateUiState()
    }

    private fun updateUiState() {
        if (isVpnActive) {
            statusText.text = "Защита 18+ активна"
            toggleButton.text = "Отключить защиту"
        } else {
            statusText.text = "Защита отключена"
            toggleButton.text = "Включить защиту"
        }
    }
}
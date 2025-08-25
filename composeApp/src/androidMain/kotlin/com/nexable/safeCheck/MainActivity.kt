package com.nexable.safeCheck

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.tooling.preview.Preview
import androidx.core.view.WindowCompat
import com.nexable.safeCheck.Login.LoginRoute

class MainActivity : ComponentActivity() {
    
    private var sharedContent: String? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        // Additional step to ensure no action bar
        WindowCompat.setDecorFitsSystemWindows(window, false)
        
        // Handle incoming shared content
        handleSharedContent(intent)
        
        setContent {
            LoginRoute(initialSharedContent = sharedContent)
        }
    }
    
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.let {
            handleSharedContent(it)
            // Update the UI with new shared content if needed
            recreate() // Simple approach - in production you'd use a more sophisticated state management
        }
    }
    
    private fun handleSharedContent(intent: Intent) {
        try {
            when (intent.action) {
                Intent.ACTION_SEND -> {
                    // Handle shared text content
                    if (intent.type == "text/plain") {
                        val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                        if (!sharedText.isNullOrBlank()) {
                            sharedContent = sharedText.trim()
                            Log.d("SafeCheck", "Received shared text: $sharedContent")
                        }
                    }
                }
                Intent.ACTION_VIEW -> {
                    // Handle URL view intents
                    val data: Uri? = intent.data
                    if (data != null) {
                        sharedContent = data.toString()
                        Log.d("SafeCheck", "Received URL to view: $sharedContent")
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("SafeCheck", "Error handling shared content", e)
            sharedContent = null
        }
    }
}

@Preview
@Composable
fun AppAndroidPreview() {
    LoginRoute()
}
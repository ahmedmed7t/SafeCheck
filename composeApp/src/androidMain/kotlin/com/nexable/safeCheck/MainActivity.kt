package com.nexable.safeCheck

import android.os.Bundle
import android.view.View
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.nexable.safeCheck.Login.LoginRoute

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        // Additional step to ensure no action bar
        WindowCompat.setDecorFitsSystemWindows(window, false)
        
        setContent {
            LoginRoute()
        }
    }
}

@Preview
@Composable
fun AppAndroidPreview() {
    LoginRoute()
}
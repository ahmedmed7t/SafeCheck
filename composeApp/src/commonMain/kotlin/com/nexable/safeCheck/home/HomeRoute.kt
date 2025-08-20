package com.nexable.safeCheck.home

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nexable.shared.*

@Composable
fun HomeRoute() {
    val scrollState = rememberScrollState()
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        BackgroundColor,
                        SurfaceColor
                    )
                )
            )
            .verticalScroll(scrollState)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(32.dp))
        
        // Shield Icon
        Text(
            text = "🛡️",
            fontSize = 80.sp,
            modifier = Modifier.size(80.dp)
        )
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // Security Scan Title
        Text(
            text = "Security Scan",
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            color = PrimaryColor,
            textAlign = TextAlign.Center
        )
        
        Spacer(modifier = Modifier.height(48.dp))
        
        // Scan a Link Section
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp),
            colors = CardDefaults.cardColors(
                containerColor = SurfaceColor.copy(alpha = 0.3f)
            ),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "Scan a Link",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = OnBackgroundColor
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Check if a link is safe or malicious",
                    fontSize = 16.sp,
                    color = OnSurfaceColor,
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Scan Button
                Button(
                    onClick = { /* TODO: Implement scan functionality */ },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = PrimaryColor
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Text(
                        text = "SCAN",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
            }
        }
        
        Spacer(modifier = Modifier.height(40.dp))
        
        // Features Section
        Text(
            text = "FEATURES",
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = PrimaryColor,
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 8.dp),
            textAlign = TextAlign.Start
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Feature Cards
        FeatureCard(
            icon = Icons.Default.Home,
            title = "File Scan",
            subtitle = "Scan files for threats",
            onClick = { /* TODO: Navigate to file scan */ }
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        FeatureCard(
            icon = Icons.Default.Lock,
            title = "Browsing Protection",
            subtitle = "Autonow on",
            hasToggle = true,
            isToggleOn = true,
            onClick = { /* TODO: Handle browsing protection toggle */ }
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        FeatureCard(
            icon = Icons.Default.Info,
            title = "Security Tips",
            subtitle = "Improve your online safety",
            onClick = { /* TODO: Navigate to security tips */ }
        )
        
        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
private fun FeatureCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    hasToggle: Boolean = false,
    isToggleOn: Boolean = false,
    onClick: () -> Unit
) {
    var toggleState by remember { mutableStateOf(isToggleOn) }
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = SurfaceColor.copy(alpha = 0.3f)
        ),
        shape = RoundedCornerShape(16.dp),
        onClick = onClick
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icon
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(PrimaryColor.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = PrimaryColor,
                    modifier = Modifier.size(24.dp)
                )
            }
            
            Spacer(modifier = Modifier.width(16.dp))
            
            // Text Content
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = title,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = OnBackgroundColor
                )
                Text(
                    text = subtitle,
                    fontSize = 14.sp,
                    color = OnSurfaceColor
                )
            }
            
            // Toggle or Arrow
            if (hasToggle) {
                Switch(
                    checked = toggleState,
                    onCheckedChange = { 
                        toggleState = it
                        onClick()
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = PrimaryColor,
                        uncheckedThumbColor = Color.Gray,
                        uncheckedTrackColor = Color.DarkGray
                    )
                )
            } else {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = "Navigate",
                    tint = OnSurfaceColor,
                    modifier = Modifier.size(24.dp)
                )
            }
        }
    }
}
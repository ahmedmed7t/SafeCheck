package com.nexable.safecheck.core.platform.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nexable.safecheck.core.platform.permissions.Permission

/**
 * Composable for displaying permission request UI with explanations.
 */
@Composable
fun PermissionRequestCard(
    permission: Permission,
    isGranted: Boolean,
    onRequestPermission: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    val permissionInfo = getPermissionInfo(permission)
    
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isGranted) Color(0xFF1B5E20) else Color(0xFF424242)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = permissionInfo.icon,
                    contentDescription = null,
                    tint = if (isGranted) Color.White else Color(0xFF5DDBD9),
                    modifier = Modifier.size(32.dp)
                )
                
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = permissionInfo.title,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                    
                    if (isGranted) {
                        Text(
                            text = "✓ Permission Granted",
                            fontSize = 14.sp,
                            color = Color(0xFF81C784)
                        )
                    }
                }
                
                if (isGranted) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = "Granted",
                        tint = Color(0xFF81C784),
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
            
            if (!isGranted) {
                Text(
                    text = permissionInfo.description,
                    fontSize = 14.sp,
                    color = Color(0xFFB0C4DE),
                    lineHeight = 20.sp
                )
                
                Text(
                    text = "Why we need this:",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White
                )
                
                Text(
                    text = permissionInfo.rationale,
                    fontSize = 14.sp,
                    color = Color(0xFFB0C4DE),
                    lineHeight = 20.sp
                )
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onOpenSettings,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color(0xFF5DDBD9)
                        ),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp, 
                            Color(0xFF5DDBD9)
                        )
                    ) {
                        Text("Settings")
                    }
                    
                    Button(
                        onClick = onRequestPermission,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF5DDBD9)
                        )
                    ) {
                        Text(
                            text = "Grant Permission",
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

/**
 * Composable for displaying a list of permission requests.
 */
@Composable
fun PermissionRequestDialog(
    permissions: List<Permission>,
    grantedPermissions: Set<Permission>,
    onRequestPermission: (Permission) -> Unit,
    onRequestAllPermissions: () -> Unit,
    onOpenSettings: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val ungrantedPermissions = permissions.filter { it !in grantedPermissions }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Permissions Required",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = if (ungrantedPermissions.size == 1) {
                        "SafeCheck needs the following permission to provide you with the best security scanning experience:"
                    } else {
                        "SafeCheck needs the following permissions to provide you with the best security scanning experience:"
                    },
                    fontSize = 14.sp,
                    lineHeight = 20.sp
                )
                
                ungrantedPermissions.forEach { permission ->
                    PermissionItem(permission = permission)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onRequestAllPermissions,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF5DDBD9)
                )
            ) {
                Text(
                    text = if (ungrantedPermissions.size == 1) "Grant Permission" else "Grant All",
                    color = Color.White
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Not Now")
            }
        }
    )
}

/**
 * Composable for displaying a single permission item in a list.
 */
@Composable
private fun PermissionItem(
    permission: Permission,
    modifier: Modifier = Modifier
) {
    val permissionInfo = getPermissionInfo(permission)
    
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Icon(
            imageVector = permissionInfo.icon,
            contentDescription = null,
            tint = Color(0xFF5DDBD9),
            modifier = Modifier.size(24.dp)
        )
        
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = permissionInfo.title,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = permissionInfo.shortDescription,
                fontSize = 12.sp,
                color = Color(0xFF666666)
            )
        }
    }
}

/**
 * Composable for showing permission rationale.
 */
@Composable
fun PermissionRationaleCard(
    permission: Permission,
    onContinue: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    val permissionInfo = getPermissionInfo(permission)
    
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1E1E1E)
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = permissionInfo.icon,
                    contentDescription = null,
                    tint = Color(0xFF5DDBD9),
                    modifier = Modifier.size(32.dp)
                )
                
                Text(
                    text = permissionInfo.title,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }
            
            Text(
                text = permissionInfo.rationale,
                fontSize = 16.sp,
                color = Color(0xFFB0C4DE),
                lineHeight = 24.sp
            )
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onCancel,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color(0xFFB0C4DE)
                    )
                ) {
                    Text("Not Now")
                }
                
                Button(
                    onClick = onContinue,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF5DDBD9)
                    )
                ) {
                    Text(
                        text = "Continue",
                        color = Color.White
                    )
                }
            }
        }
    }
}

/**
 * Data class containing permission information for UI display.
 */
data class PermissionInfo(
    val title: String,
    val description: String,
    val shortDescription: String,
    val rationale: String,
    val icon: ImageVector
)

/**
 * Gets UI information for a specific permission.
 */
private fun getPermissionInfo(permission: Permission): PermissionInfo {
    return when (permission) {
        Permission.CAMERA -> PermissionInfo(
            title = "Camera Access",
            description = "SafeCheck needs camera access to scan QR codes that may contain suspicious URLs or content.",
            shortDescription = "Scan QR codes for security analysis",
            rationale = "We use your camera exclusively to scan QR codes and analyze their content for potential security threats. Your camera feed is not stored or transmitted anywhere.",
            icon = Icons.Default.PhotoCamera
        )
        
        Permission.INTERNET -> PermissionInfo(
            title = "Internet Access",
            description = "SafeCheck needs internet access to perform real-time security checks and reputation lookups.",
            shortDescription = "Perform online security checks",
            rationale = "We need internet access to check URLs against threat databases, perform DNS lookups, and validate certificates. This ensures you get the most up-to-date security information.",
            icon = Icons.Default.Language
        )
        
        Permission.NETWORK_STATE -> PermissionInfo(
            title = "Network State",
            description = "SafeCheck needs to check your network connection status to optimize security scanning.",
            shortDescription = "Check network connectivity",
            rationale = "We check your network status to determine when to perform online security checks and when to work offline. This helps preserve your data usage.",
            icon = Icons.Default.NetworkCheck
        )
        
        Permission.STORAGE -> PermissionInfo(
            title = "Storage Access",
            description = "SafeCheck needs storage access to cache security data and save scan history.",
            shortDescription = "Store scan results and cache data",
            rationale = "We use storage to cache threat databases for faster scanning and to save your scan history locally. This improves performance and allows offline functionality.",
            icon = Icons.Default.Storage
        )
        
        Permission.MICROPHONE -> PermissionInfo(
            title = "Microphone Access",
            description = "SafeCheck may need microphone access for certain scanning features.",
            shortDescription = "Enhanced scanning capabilities",
            rationale = "Microphone access may be used for advanced scanning features or voice-based interactions. This permission is optional for core functionality.",
            icon = Icons.Default.Mic
        )
        
        Permission.LOCATION -> PermissionInfo(
            title = "Location Access",
            description = "SafeCheck may use location data to provide region-specific security insights.",
            shortDescription = "Region-specific security analysis",
            rationale = "Location data helps us provide more relevant security warnings based on threats common in your region. This information is processed locally and not shared.",
            icon = Icons.Default.LocationOn
        )
        
        Permission.WRITE_EXTERNAL_STORAGE -> PermissionInfo(
            title = "External Storage Write",
            description = "SafeCheck needs write access to save security reports and export data.",
            shortDescription = "Save reports and export data",
            rationale = "We need write access to save detailed security reports and allow you to export your scan history for your records.",
            icon = Icons.Default.Save
        )
        
        Permission.READ_EXTERNAL_STORAGE -> PermissionInfo(
            title = "External Storage Read",
            description = "SafeCheck needs read access to analyze files and import security data.",
            shortDescription = "Analyze files and import data",
            rationale = "We need read access to scan files for security threats and to import threat intelligence databases for enhanced protection.",
            icon = Icons.Default.FolderOpen
        )
    }
}

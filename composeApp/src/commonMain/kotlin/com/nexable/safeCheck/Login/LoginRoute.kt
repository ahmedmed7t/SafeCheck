package com.nexable.safeCheck.Login

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.jetbrains.compose.resources.painterResource
import safecheck.composeapp.generated.resources.Res
import safecheck.composeapp.generated.resources.adaptive_logo

@Composable
fun LoginRoute(initialSharedContent: String? = null) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF002C43), // Dark blue
                        Color(0xFF2D5A8A), // Medium blue
                        Color(0xFF002C43)  // Lighter blue
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(modifier = Modifier.height(102.dp))
            // Shield Icon with Checkmark
            ShieldIcon()

            Spacer(modifier = Modifier.height(32.dp))

            // Title
            Text(
                text = "Verify Before You Trust",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF5DDBD9), // Teal color
                textAlign = TextAlign.Center,
                letterSpacing = 2.sp
            )

            Spacer(modifier = Modifier.height(48.dp))

            // Username Field
            LoginTextField(
                value = username,
                onValueChange = { username = it },
                label = "Username",
//                leadingIcon = Icons.Default.Person
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Password Field
            LoginTextField(
                value = password,
                onValueChange = { password = it },
                label = "Password",
//                leadingIcon = Icons.Default.Lock,
                isPassword = true
            )

            Spacer(modifier = Modifier.weight(1f))

            // Login Button
            Button(
                onClick = { 
                    // Handle login
                    // TODO: After successful login, if initialSharedContent is not null,
                    // navigate to main screen with the shared content pre-filled
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF5DDBD9) // Teal color
                ),
                shape = RoundedCornerShape(28.dp)
            ) {
                Text(
                    text = "LOG IN",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White,
                    letterSpacing = 1.sp
                )
            }
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}

@Composable
private fun ShieldIcon() {
    Box(
        modifier = Modifier
            .size(180.dp),
        contentAlignment = Alignment.Center
    ) {
        Image(
            painter = painterResource(Res.drawable.adaptive_logo),
            contentDescription = ""
        )
    }
}

@Composable
private fun LoginTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    leadingIcon: ImageVector? = null,
    isPassword: Boolean = false
) {
    TextField(
        value = value,
        onValueChange = onValueChange,
        label = {
            Text(
                text = label,
                color = Color(0xFFB0C4DE)
            )
        },
        leadingIcon = leadingIcon?.let { icon ->
            {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = Color(0xFF5DDBD9)
                )
            }
        },
        visualTransformation = if (isPassword) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = if (isPassword) KeyboardOptions(keyboardType = KeyboardType.Password) else KeyboardOptions.Default,
        modifier = Modifier.fillMaxWidth(),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Color(0xFF5DDBD9),
            unfocusedBorderColor = Color(0xFFB0C4DE),
            focusedTextColor = Color.White,
            unfocusedTextColor = Color.White,
            cursorColor = Color(0xFF5DDBD9)
        ),
        singleLine = true
    )
}


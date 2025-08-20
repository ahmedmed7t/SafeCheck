package com.nexable.shared

import androidx.compose.runtime.Composable
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import org.jetbrains.compose.resources.Font
import safecheck.shared.generated.resources.Res
import safecheck.shared.generated.resources.roboto_regular

object FontSize {
    val EXTRA_SMALL = 10.sp
    val SMALL = 12.sp
    val REGULAR = 14.sp
    val EXTRA_REGULAR = 16.sp
    val MEDIUM = 18.sp
    val EXTRA_MEDIUM = 20.sp
    val LARGE = 30.sp
    val EXTRA_LARGE = 40.sp
}


@Composable
fun RegularFont() = FontFamily(
    Font(Res.font.roboto_regular, FontWeight.Normal)
)

//@Composable
//fun BoldFont() = FontFamily(
//    Font(Res.font.roboto_bold, FontWeight.Bold)
//)
//
//@Composable
//fun SemiBoldFont() = FontFamily(
//    Font(Res.font.roboto_semi_bold, FontWeight.SemiBold)
//)
//
//@Composable
//fun ExtraBoldFont() = FontFamily(
//    Font(Res.font.roboto_extra_bold, FontWeight.ExtraBold)
//)
//
//@Composable
//fun LightFont() = FontFamily(
//    Font(Res.font.roboto_light, FontWeight.Light)
//)
//
//@Composable
//fun ThinFont() = FontFamily(
//    Font(Res.font.roboto_thin, FontWeight.Thin)
//)
//
//@Composable
//fun MediumFont() = FontFamily(
//    Font(Res.font.roboto_medium, FontWeight.Medium)
//)
package com.nexable.safecheck.core.platform.qr

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.flow.Flow
import kotlinx.datetime.Clock

/**
 * Platform-specific QR code scanning interface.
 * Provides QR code detection and content extraction capabilities.
 */
expect class QrScanner() {
    
    /**
     * Starts QR code scanning and returns a flow of detected codes.
     * 
     * @return Flow of QR scan results
     */
    fun startScanning(): Flow<Result<QrScanResult>>
    
    /**
     * Stops QR code scanning.
     */
    suspend fun stopScanning()
    
    /**
     * Checks if camera permission is granted.
     * 
     * @return Result indicating permission status
     */
    suspend fun hasCameraPermission(): Result<Boolean>
    
    /**
     * Requests camera permission.
     * 
     * @return Result indicating if permission was granted
     */
    suspend fun requestCameraPermission(): Result<Boolean>
    
    /**
     * Checks if the device has a camera.
     * 
     * @return Result indicating camera availability
     */
    suspend fun isCameraAvailable(): Result<Boolean>
}

/**
 * QR code scan result.
 */
data class QrScanResult(
    val content: String,
    val format: QrCodeFormat,
    val rawBytes: ByteArray? = null,
    val boundingBox: BoundingBox? = null,
    val timestamp: Long = Clock.System.now().toEpochMilliseconds(),
    val confidence: Float = 1.0f
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as QrScanResult

        if (content != other.content) return false
        if (format != other.format) return false
        if (rawBytes != null) {
            if (other.rawBytes == null) return false
            if (!rawBytes.contentEquals(other.rawBytes)) return false
        } else if (other.rawBytes != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = content.hashCode()
        result = 31 * result + format.hashCode()
        result = 31 * result + (rawBytes?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * QR code format types.
 */
enum class QrCodeFormat {
    QR_CODE,
    DATA_MATRIX,
    AZTEC,
    PDF_417,
    CODE_128,
    CODE_39,
    EAN_8,
    EAN_13,
    UPC_A,
    UPC_E,
    CODABAR,
    ITF,
    RSS_14,
    RSS_EXPANDED,
    UNKNOWN
}

/**
 * Bounding box coordinates for detected QR code.
 */
data class BoundingBox(
    val left: Int,
    val top: Int,
    val right: Int,
    val bottom: Int
) {
    val width: Int = right - left
    val height: Int = bottom - top
    val centerX: Int = left + width / 2
    val centerY: Int = top + height / 2
}

/**
 * QR scanner configuration.
 */
data class QrScannerConfig(
    val supportedFormats: Set<QrCodeFormat> = setOf(QrCodeFormat.QR_CODE),
    val enableTorch: Boolean = false,
    val autoFocus: Boolean = true,
    val scanRect: BoundingBox? = null,
    val analysisResolution: ScanResolution = ScanResolution.MEDIUM
)

/**
 * Analysis resolution for QR scanning.
 */
enum class ScanResolution {
    LOW,    // 480p
    MEDIUM, // 720p
    HIGH    // 1080p+
}

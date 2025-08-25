package com.nexable.safecheck.core.platform.qr

import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.platform.permissions.PermissionManager
import com.nexable.safecheck.core.platform.permissions.Permission
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.datetime.Clock
import platform.AVFoundation.*
import platform.CoreGraphics.*
import platform.Foundation.*
import platform.UIKit.*

/**
 * iOS implementation of QR scanner using AVFoundation.
 */
actual class QrScanner : NSObject(), AVCaptureMetadataOutputObjectsDelegateProtocol {
    
    private var captureSession: AVCaptureSession? = null
    private var videoPreviewLayer: AVCaptureVideoPreviewLayer? = null
    private var captureDevice: AVCaptureDevice? = null
    private var metadataOutput: AVCaptureMetadataOutput? = null
    private val scanResults = Channel<Result<QrScanResult>>(Channel.UNLIMITED)
    private var isScanning = false
    private var permissionManager: PermissionManager? = null
    
    /**
     * Initialize the QR scanner with permission manager.
     */
    fun initialize(permissionManager: PermissionManager? = null) {
        this.permissionManager = permissionManager ?: PermissionManager.create()
    }
    
    actual fun startScanning(): Flow<Result<QrScanResult>> = flow {
        if (isScanning) {
            emit(Result.error("Scanner is already running", "SCANNER_ALREADY_RUNNING"))
            return@flow
        }
        
        val permissionResult = hasCameraPermission()
        when (permissionResult) {
            is Result.Success -> {
                if (!permissionResult.data) {
                    emit(Result.error("Camera permission required", "CAMERA_PERMISSION_REQUIRED"))
                    return@flow
                }
            }
            is Result.Error -> {
                emit(permissionResult)
                return@flow
            }
            is Result.Loading -> {
                emit(permissionResult)
                return@flow
            }
        }
        
        try {
            setupCaptureSession()
            startCaptureSession()
            isScanning = true
            
            // Emit scan results as they come in
            for (result in scanResults) {
                emit(result)
            }
            
        } catch (e: Exception) {
            emit(Result.error("Failed to start camera: ${e.message}", "CAMERA_START_FAILED"))
        }
    }
    
    actual suspend fun stopScanning() {
        try {
            isScanning = false
            captureSession?.stopRunning()
            scanResults.close()
        } catch (e: Exception) {
            // Silently handle stop errors
        }
    }
    
    actual suspend fun hasCameraPermission(): Result<Boolean> {
        val permManager = permissionManager ?: return Result.error("Permission manager not available", "PERMISSION_MANAGER_NOT_AVAILABLE")
        
        return permManager.isPermissionGranted(Permission.CAMERA)
    }
    
    actual suspend fun requestCameraPermission(): Result<Boolean> {
        val permManager = permissionManager ?: return Result.error("Permission manager not available", "PERMISSION_MANAGER_NOT_AVAILABLE")
        
        return permManager.requestPermission(Permission.CAMERA)
    }
    
    actual suspend fun isCameraAvailable(): Result<Boolean> {
        return try {
            val device = AVCaptureDevice.defaultDeviceWithMediaType(AVMediaTypeVideo)
            Result.success(device != null)
        } catch (e: Exception) {
            Result.error("Failed to check camera availability: ${e.message}", "CAMERA_CHECK_FAILED")
        }
    }
    
    private fun setupCaptureSession() {
        // Create capture session
        captureSession = AVCaptureSession()
        captureSession?.sessionPreset = AVCaptureSessionPresetHigh
        
        // Get camera device
        captureDevice = AVCaptureDevice.defaultDeviceWithMediaType(AVMediaTypeVideo)
        
        if (captureDevice == null) {
            scanResults.trySend(Result.error("No camera device available", "NO_CAMERA_DEVICE"))
            return
        }
        
        try {
            // Create input
            val input = AVCaptureDeviceInput.deviceInputWithDevice(captureDevice!!, null)
            
            if (input == null) {
                scanResults.trySend(Result.error("Failed to create camera input", "CAMERA_INPUT_FAILED"))
                return
            }
            
            // Add input to session
            if (captureSession?.canAddInput(input) == true) {
                captureSession?.addInput(input)
            } else {
                scanResults.trySend(Result.error("Cannot add camera input to session", "CAMERA_INPUT_ADD_FAILED"))
                return
            }
            
            // Create metadata output
            metadataOutput = AVCaptureMetadataOutput()
            
            if (captureSession?.canAddOutput(metadataOutput!!) == true) {
                captureSession?.addOutput(metadataOutput!!)
                
                // Set delegate for metadata output
                metadataOutput?.setMetadataObjectsDelegate(this, dispatch_get_main_queue())
                
                // Set metadata object types to scan
                metadataOutput?.metadataObjectTypes = listOf(
                    AVMetadataObjectTypeQRCode,
                    AVMetadataObjectTypeDataMatrixCode,
                    AVMetadataObjectTypeAztecCode,
                    AVMetadataObjectTypePDF417Code,
                    AVMetadataObjectTypeCode128Code,
                    AVMetadataObjectTypeCode39Code,
                    AVMetadataObjectTypeEAN8Code,
                    AVMetadataObjectTypeEAN13Code,
                    AVMetadataObjectTypeUPCECode
                )
            } else {
                scanResults.trySend(Result.error("Cannot add metadata output to session", "METADATA_OUTPUT_ADD_FAILED"))
                return
            }
            
        } catch (e: Exception) {
            scanResults.trySend(Result.error("Failed to setup capture session: ${e.message}", "CAPTURE_SESSION_SETUP_FAILED"))
        }
    }
    
    private fun startCaptureSession() {
        try {
            captureSession?.startRunning()
        } catch (e: Exception) {
            scanResults.trySend(Result.error("Failed to start capture session: ${e.message}", "CAPTURE_SESSION_START_FAILED"))
        }
    }
    
    // AVCaptureMetadataOutputObjectsDelegate implementation
    override fun captureOutput(
        output: AVCaptureOutput,
        didOutputMetadataObjects: List<*>,
        fromConnection: AVCaptureConnection
    ) {
        for (metadataObject in didOutputMetadataObjects) {
            if (metadataObject is AVMetadataMachineReadableCodeObject) {
                val qrResult = convertToQrScanResult(metadataObject)
                scanResults.trySend(Result.success(qrResult))
            }
        }
    }
    
    private fun convertToQrScanResult(metadataObject: AVMetadataMachineReadableCodeObject): QrScanResult {
        val content = metadataObject.stringValue ?: ""
        val format = when (metadataObject.type) {
            AVMetadataObjectTypeQRCode -> QrCodeFormat.QR_CODE
            AVMetadataObjectTypeDataMatrixCode -> QrCodeFormat.DATA_MATRIX
            AVMetadataObjectTypeAztecCode -> QrCodeFormat.AZTEC
            AVMetadataObjectTypePDF417Code -> QrCodeFormat.PDF_417
            AVMetadataObjectTypeCode128Code -> QrCodeFormat.CODE_128
            AVMetadataObjectTypeCode39Code -> QrCodeFormat.CODE_39
            AVMetadataObjectTypeEAN8Code -> QrCodeFormat.EAN_8
            AVMetadataObjectTypeEAN13Code -> QrCodeFormat.EAN_13
            AVMetadataObjectTypeUPCECode -> QrCodeFormat.UPC_E
            else -> QrCodeFormat.UNKNOWN
        }
        
        val boundingBox = metadataObject.bounds.let { bounds ->
            BoundingBox(
                left = bounds.origin.x.toInt(),
                top = bounds.origin.y.toInt(),
                right = (bounds.origin.x + bounds.size.width).toInt(),
                bottom = (bounds.origin.y + bounds.size.height).toInt()
            )
        }
        
        return QrScanResult(
            content = content,
            format = format,
            rawBytes = null, // AVFoundation doesn't provide raw bytes easily
            boundingBox = boundingBox,
            timestamp = Clock.System.now().toEpochMilliseconds(),
            confidence = 1.0f // AVFoundation doesn't provide confidence score
        )
    }
    
    /**
     * Gets the preview layer for displaying camera feed.
     */
    fun getPreviewLayer(): AVCaptureVideoPreviewLayer? {
        if (videoPreviewLayer == null && captureSession != null) {
            videoPreviewLayer = AVCaptureVideoPreviewLayer.layerWithSession(captureSession!!)
            videoPreviewLayer?.videoGravity = AVLayerVideoGravityResizeAspectFill
        }
        return videoPreviewLayer
    }
    
    /**
     * Sets the scan area to focus on a specific region.
     */
    fun setScanArea(scanRect: CGRect) {
        metadataOutput?.rectOfInterest = scanRect
    }
    
    /**
     * Enables or disables the torch (flashlight).
     */
    fun setTorchEnabled(enabled: Boolean): Result<Unit> {
        return try {
            val device = captureDevice
            if (device?.hasTorch == true) {
                device.lockForConfiguration(null)
                device.torchMode = if (enabled) AVCaptureTorchModeOn else AVCaptureTorchModeOff
                device.unlockForConfiguration()
                Result.success(Unit)
            } else {
                Result.error("Torch not available", "TORCH_NOT_AVAILABLE")
            }
        } catch (e: Exception) {
            Result.error("Failed to set torch: ${e.message}", "TORCH_SET_FAILED")
        }
    }
    
    /**
     * Checks if torch is available.
     */
    fun isTorchAvailable(): Boolean {
        return captureDevice?.hasTorch ?: false
    }
    
    /**
     * Sets the focus point for the camera.
     */
    fun setFocusPoint(point: CGPoint): Result<Unit> {
        return try {
            val device = captureDevice
            if (device?.focusPointOfInterestSupported == true) {
                device.lockForConfiguration(null)
                device.focusPointOfInterest = point
                device.focusMode = AVCaptureFocusModeAutoFocus
                device.unlockForConfiguration()
                Result.success(Unit)
            } else {
                Result.error("Focus point not supported", "FOCUS_POINT_NOT_SUPPORTED")
            }
        } catch (e: Exception) {
            Result.error("Failed to set focus point: ${e.message}", "FOCUS_POINT_SET_FAILED")
        }
    }
    
    fun cleanup() {
        try {
            kotlinx.coroutines.runBlocking {
                stopScanning()
            }
            captureSession = null
            videoPreviewLayer = null
            captureDevice = null
            metadataOutput = null
        } catch (e: Exception) {
            // Silently handle cleanup errors
        }
    }
    
    companion object {
        /**
         * Create and initialize QR scanner.
         */
        fun create(permissionManager: PermissionManager? = null): QrScanner {
            val scanner = QrScanner()
            scanner.initialize(permissionManager)
            return scanner
        }
        
        /**
         * Privacy description that should be added to Info.plist:
         * NSCameraUsageDescription = "SafeCheck uses the camera to scan QR codes that may contain URLs, emails, or other content for security analysis. This helps protect you from malicious QR codes."
         */
        const val CAMERA_USAGE_DESCRIPTION = "SafeCheck uses the camera to scan QR codes that may contain URLs, emails, or other content for security analysis. This helps protect you from malicious QR codes."
    }
}

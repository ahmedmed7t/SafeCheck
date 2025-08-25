package com.nexable.safecheck.core.platform.qr

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.platform.permissions.PermissionManager
import com.nexable.safecheck.core.platform.permissions.Permission
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.datetime.Clock
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.coroutines.resume

/**
 * Android implementation of QR scanner using CameraX and ML Kit.
 */
actual class QrScanner {
    private var context: Context? = null
    private var lifecycleOwner: LifecycleOwner? = null
    private var cameraProvider: ProcessCameraProvider? = null
    private var imageAnalysis: ImageAnalysis? = null
    private var camera: Camera? = null
    private var cameraExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val barcodeScanner = BarcodeScanning.getClient()
    private val scanResults = Channel<Result<QrScanResult>>(Channel.UNLIMITED)
    private var isScanning = false
    private var permissionManager: PermissionManager? = null
    
    /**
     * Initialize the QR scanner with Android context and lifecycle owner.
     */
    fun initialize(context: Context, lifecycleOwner: LifecycleOwner, permissionManager: PermissionManager? = null) {
        this.context = context
        this.lifecycleOwner = lifecycleOwner
        this.permissionManager = permissionManager ?: PermissionManager.create(context)
    }
    
    actual fun startScanning(): Flow<Result<QrScanResult>> = flow {
        if (isScanning) {
            emit(Result.error("Scanner is already running", "SCANNER_ALREADY_RUNNING"))
            return@flow
        }
        
        val ctx = context ?: run {
            emit(Result.error("Scanner not initialized", "SCANNER_NOT_INITIALIZED"))
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
            val provider = suspendCancellableCoroutine<ProcessCameraProvider> { continuation ->
                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                cameraProviderFuture.addListener({
                    try {
                        continuation.resume(cameraProviderFuture.get())
                    } catch (e: Exception) {
                        continuation.cancel(e)
                    }
                }, ContextCompat.getMainExecutor(ctx))
                
                continuation.invokeOnCancellation {
                    cameraProviderFuture.cancel(true)
                }
            }
            
            cameraProvider = provider
            startCamera()
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
            camera = null
            imageAnalysis = null
            cameraProvider?.unbindAll()
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
        val ctx = context ?: return Result.error("Context not available", "CONTEXT_NOT_AVAILABLE")
        
        val hasCamera = ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
        return Result.success(hasCamera)
    }
    
    private fun startCamera() {
        val ctx = context ?: return
        val lifecycleOwner = lifecycleOwner ?: return
        val cameraProvider = cameraProvider ?: return
        
        try {
            // Preview use case
            val preview = Preview.Builder().build()
            
            // Image analysis use case for QR detection
            imageAnalysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            
            imageAnalysis?.setAnalyzer(cameraExecutor) { imageProxy ->
                @androidx.camera.core.ExperimentalGetImage
                processImageProxy(imageProxy)
            }
            
            // Select back camera as default
            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            
            try {
                // Unbind use cases before rebinding
                cameraProvider.unbindAll()
                
                // Bind use cases to camera
                camera = cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    cameraSelector,
                    preview,
                    imageAnalysis
                )
                
            } catch (e: Exception) {
                scanResults.trySend(Result.error("Camera binding failed: ${e.message}", "CAMERA_BINDING_FAILED"))
            }
            
        } catch (e: Exception) {
            scanResults.trySend(Result.error("Camera setup failed: ${e.message}", "CAMERA_SETUP_FAILED"))
        }
    }
    
    @androidx.camera.core.ExperimentalGetImage
    private fun processImageProxy(imageProxy: ImageProxy) {
        val image = imageProxy.image
        if (image != null) {
            val inputImage = InputImage.fromMediaImage(image, imageProxy.imageInfo.rotationDegrees)
            
            barcodeScanner.process(inputImage)
                .addOnSuccessListener { barcodes ->
                    for (barcode in barcodes) {
                        val qrResult = convertToQrScanResult(barcode)
                        scanResults.trySend(Result.success(qrResult))
                    }
                }
                .addOnFailureListener { e ->
                    scanResults.trySend(Result.error("QR processing failed: ${e.message}", "QR_PROCESSING_FAILED"))
                }
                .addOnCompleteListener {
                    imageProxy.close()
                }
        } else {
            imageProxy.close()
        }
    }
    
    private fun convertToQrScanResult(barcode: Barcode): QrScanResult {
        val content = barcode.displayValue ?: ""
        val format = when (barcode.format) {
            Barcode.FORMAT_QR_CODE -> QrCodeFormat.QR_CODE
            Barcode.FORMAT_DATA_MATRIX -> QrCodeFormat.DATA_MATRIX
            Barcode.FORMAT_AZTEC -> QrCodeFormat.AZTEC
            Barcode.FORMAT_PDF417 -> QrCodeFormat.PDF_417
            Barcode.FORMAT_CODE_128 -> QrCodeFormat.CODE_128
            Barcode.FORMAT_CODE_39 -> QrCodeFormat.CODE_39
            Barcode.FORMAT_EAN_8 -> QrCodeFormat.EAN_8
            Barcode.FORMAT_EAN_13 -> QrCodeFormat.EAN_13
            Barcode.FORMAT_UPC_A -> QrCodeFormat.UPC_A
            Barcode.FORMAT_UPC_E -> QrCodeFormat.UPC_E
            Barcode.FORMAT_CODABAR -> QrCodeFormat.CODABAR
            Barcode.FORMAT_ITF -> QrCodeFormat.ITF
            else -> QrCodeFormat.UNKNOWN
        }
        
        val boundingBox = barcode.boundingBox?.let { rect ->
            BoundingBox(
                left = rect.left,
                top = rect.top,
                right = rect.right,
                bottom = rect.bottom
            )
        }
        
        return QrScanResult(
            content = content,
            format = format,
            rawBytes = barcode.rawBytes,
            boundingBox = boundingBox,
            timestamp = Clock.System.now().toEpochMilliseconds(),
            confidence = 1.0f // ML Kit doesn't provide confidence score
        )
    }
    
    fun cleanup() {
        try {
            kotlinx.coroutines.runBlocking {
                stopScanning()
            }
            cameraExecutor.shutdown()
            barcodeScanner.close()
        } catch (e: Exception) {
            // Silently handle cleanup errors
        }
    }
    
    companion object {
        /**
         * Create and initialize QR scanner with context and lifecycle.
         */
        fun create(context: Context, lifecycleOwner: LifecycleOwner, permissionManager: PermissionManager? = null): QrScanner {
            val scanner = QrScanner()
            scanner.initialize(context, lifecycleOwner, permissionManager)
            return scanner
        }
    }
}

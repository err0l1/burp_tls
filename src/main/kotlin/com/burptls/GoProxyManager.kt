package com.burptls

import java.io.*
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Go 代理服务器管理器
 * 负责启动、停止和管理 Go TLS 代理进程
 */
class GoProxyManager(
    private val stdout: PrintWriter,
    private val stderr: PrintWriter
) {
    private var proxyProcess: Process? = null
    private var proxyPort: Int = 0
    private var isRunning: Boolean = false
    
    companion object {
        const val DEFAULT_PORT = 18443
        const val PROXY_BINARY_NAME_WINDOWS = "tls-proxy.exe"
        const val PROXY_BINARY_NAME_UNIX = "tls-proxy"
    }
    
    /**
     * 启动 Go 代理服务器
     */
    fun start(mode: String = "transparent", fingerprint: String = "chrome_120") {
        if (isRunning) {
            stdout.println("[GoProxyManager] Proxy already running")
            return
        }
        
        // 查找可用端口
        proxyPort = findAvailablePort(DEFAULT_PORT)
        stdout.println("[GoProxyManager] Using port: $proxyPort, mode: $mode")
        
        // 提取并启动代理二进制文件
        val proxyBinary = extractProxyBinary()
        if (proxyBinary == null) {
            stderr.println("[GoProxyManager] Failed to extract proxy binary")
            stdout.println("[GoProxyManager] Please ensure tls-proxy is running on port $proxyPort")
            stdout.println("[GoProxyManager] Run: ./tls-proxy -port $proxyPort -mode $mode")
            return
        }
        
        try {
            val processBuilder = ProcessBuilder(
                proxyBinary.absolutePath,
                "-port", proxyPort.toString(),
                "-mode", mode,
                "-fingerprint", fingerprint
            )
            processBuilder.redirectErrorStream(true)
            
            proxyProcess = processBuilder.start()
            isRunning = true
            
            // 读取代理输出
            Thread {
                try {
                    proxyProcess?.inputStream?.bufferedReader()?.forEachLine { line ->
                        stdout.println("[TLS-Proxy] $line")
                    }
                } catch (e: Exception) {
                    // 进程结束
                }
            }.start()
            
            // 等待代理启动
            Thread.sleep(1000)
            
            if (proxyProcess?.isAlive == true) {
                stdout.println("[GoProxyManager] Proxy started successfully on port $proxyPort")
            } else {
                isRunning = false
                stderr.println("[GoProxyManager] Proxy failed to start")
            }
            
        } catch (e: Exception) {
            stderr.println("[GoProxyManager] Error starting proxy: ${e.message}")
            isRunning = false
        }
    }
    
    /**
     * 停止 Go 代理服务器
     */
    fun stop() {
        proxyProcess?.let { process ->
            try {
                process.destroy()
                process.waitFor()
                stdout.println("[GoProxyManager] Proxy stopped")
            } catch (e: Exception) {
                stderr.println("[GoProxyManager] Error stopping proxy: ${e.message}")
                process.destroyForcibly()
            }
        }
        proxyProcess = null
        isRunning = false
    }
    
    /**
     * 获取代理端口
     */
    fun getProxyPort(): Int = proxyPort
    
    /**
     * 检查代理是否运行中
     */
    fun isRunning(): Boolean {
        return isRunning && (proxyProcess?.isAlive == true)
    }
    
    /**
     * 查找可用端口
     */
    private fun findAvailablePort(startPort: Int): Int {
        var port = startPort
        while (port < startPort + 100) {
            try {
                ServerSocket(port).use {
                    return port
                }
            } catch (e: Exception) {
                port++
            }
        }
        return startPort
    }
    
    /**
     * 从 JAR 资源中提取代理二进制文件
     */
    private fun extractProxyBinary(): File? {
        val osName = System.getProperty("os.name").lowercase()
        val binaryName = if (osName.contains("windows")) {
            PROXY_BINARY_NAME_WINDOWS
        } else {
            PROXY_BINARY_NAME_UNIX
        }
        
        val resourcePath = "/native/$binaryName"
        
        try {
            val inputStream = javaClass.getResourceAsStream(resourcePath)
            if (inputStream == null) {
                stderr.println("[GoProxyManager] Binary not found in resources: $resourcePath")
                stderr.println("[GoProxyManager] Please compile the Go proxy manually")
                return null
            }
            
            // 创建临时文件
            val tempDir = Files.createTempDirectory("burp-tls-proxy")
            val tempFile = tempDir.resolve(binaryName).toFile()
            
            inputStream.use { input ->
                Files.copy(input, tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
            
            // 设置可执行权限（Unix）
            if (!osName.contains("windows")) {
                tempFile.setExecutable(true)
            }
            
            stdout.println("[GoProxyManager] Extracted binary to: ${tempFile.absolutePath}")
            return tempFile
            
        } catch (e: Exception) {
            stderr.println("[GoProxyManager] Error extracting binary: ${e.message}")
            return null
        }
    }
}

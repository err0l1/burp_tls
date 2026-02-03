package com.burptls

import burp.*
import java.io.PrintWriter
import javax.swing.*

/**
 * Burp Suite TLS Fingerprint Randomizer Extension
 * 
 * 通过劫持 Burp 的 HTTP 请求，转发到本地 Go 代理服务器，
 * 使用 uTLS 库实现 TLS 指纹随机化/伪装
 */
class BurpExtender : IBurpExtender, ITab, IHttpListener, IExtensionStateListener {
    
    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var stdout: PrintWriter
    private lateinit var stderr: PrintWriter
    
    private lateinit var mainPanel: TlsConfigPanel
    private lateinit var proxyManager: GoProxyManager
    
    companion object {
        const val EXTENSION_NAME = "TLS Fingerprint Randomizer"
        const val VERSION = "1.0.0"
    }
    
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        this.helpers = callbacks.helpers
        this.stdout = PrintWriter(callbacks.stdout, true)
        this.stderr = PrintWriter(callbacks.stderr, true)
        
        callbacks.setExtensionName(EXTENSION_NAME)
        
        stdout.println("[$EXTENSION_NAME] v$VERSION Loading...")
        
        // 初始化 Go 代理管理器
        proxyManager = GoProxyManager(stdout, stderr)
        
        // 创建 UI
        SwingUtilities.invokeLater {
            mainPanel = TlsConfigPanel(callbacks, proxyManager)
            callbacks.addSuiteTab(this)
        }
        
        // 注册 HTTP 监听器
        callbacks.registerHttpListener(this)
        
        // 注册扩展状态监听器
        callbacks.registerExtensionStateListener(this)
        
        // 启动 Go 代理服务器
        try {
            proxyManager.start()
            stdout.println("[$EXTENSION_NAME] Go proxy server started successfully")
        } catch (e: Exception) {
            stderr.println("[$EXTENSION_NAME] Failed to start Go proxy: ${e.message}")
        }
        
        stdout.println("[$EXTENSION_NAME] Extension loaded successfully")
    }
    
    override fun getTabCaption(): String = "TLS Fingerprint"
    
    override fun getUiComponent(): java.awt.Component = mainPanel
    
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if (!messageIsRequest) return
        if (!mainPanel.isTlsEnabled()) return
        
        // 检查是否需要处理此请求
        val service = messageInfo.httpService
        if (service.protocol != "https") return
        
        // 修改请求，通过 Go 代理转发（使用 HTTP 连接到本地代理）
        try {
            val newService = helpers.buildHttpService(
                "127.0.0.1",
                proxyManager.getProxyPort(),
                false  // 使用 HTTP 连接到本地代理
            )
            
            // 添加原始目标主机头
            val request = messageInfo.request
            val analyzedRequest = helpers.analyzeRequest(messageInfo)
            val headers = analyzedRequest.headers.toMutableList()
            
            // 添加自定义头以传递原始目标
            headers.add("X-TLS-Target-Host: ${service.host}")
            headers.add("X-TLS-Target-Port: ${service.port}")
            headers.add("X-TLS-Fingerprint: ${mainPanel.getSelectedFingerprint()}")
            
            val body = request.copyOfRange(analyzedRequest.bodyOffset, request.size)
            val newRequest = helpers.buildHttpMessage(headers, body)
            
            messageInfo.request = newRequest
            messageInfo.httpService = newService
            
        } catch (e: Exception) {
            stderr.println("[$EXTENSION_NAME] Error processing request: ${e.message}")
        }
    }
    
    override fun extensionUnloaded() {
        stdout.println("[$EXTENSION_NAME] Unloading extension...")
        proxyManager.stop()
        stdout.println("[$EXTENSION_NAME] Extension unloaded")
    }
}

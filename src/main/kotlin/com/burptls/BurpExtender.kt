package com.burptls

import burp.*
import java.io.PrintWriter
import javax.swing.*

/**
 * Burp Suite TLS Fingerprint Randomizer Extension
 * 
 * 启动 Go TLS 代理，需要在 Burp 中配置上游代理
 * Go 代理使用 uTLS 库实现 TLS 指纹伪装
 */
class BurpExtender : IBurpExtender, ITab, IExtensionStateListener {
    
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
        
        // 注册扩展状态监听器
        callbacks.registerExtensionStateListener(this)
        
        // 启动 Go 代理服务器
        try {
            proxyManager.start()
            val port = proxyManager.getProxyPort()
            stdout.println("[$EXTENSION_NAME] ========================================")
            stdout.println("[$EXTENSION_NAME] Go TLS 代理已启动，端口: $port")
            stdout.println("[$EXTENSION_NAME] ")
            stdout.println("[$EXTENSION_NAME] 配置方法:")
            stdout.println("[$EXTENSION_NAME] 1. Settings -> Network -> Connections")
            stdout.println("[$EXTENSION_NAME] 2. Upstream proxy servers -> Add")
            stdout.println("[$EXTENSION_NAME] 3. Destination: *  Proxy: 127.0.0.1:$port")
            stdout.println("[$EXTENSION_NAME] ========================================")
        } catch (e: Exception) {
            stderr.println("[$EXTENSION_NAME] Failed to start Go proxy: ${e.message}")
        }
        
        stdout.println("[$EXTENSION_NAME] Extension loaded successfully")
    }
    
    override fun getTabCaption(): String = "TLS Fingerprint"
    
    override fun getUiComponent(): java.awt.Component = mainPanel
    
    override fun extensionUnloaded() {
        stdout.println("[$EXTENSION_NAME] Unloading extension...")
        proxyManager.stop()
        stdout.println("[$EXTENSION_NAME] Extension unloaded")
    }
}

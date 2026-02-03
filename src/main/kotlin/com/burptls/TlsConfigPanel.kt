package com.burptls

import burp.IBurpExtenderCallbacks
import java.awt.*
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.border.TitledBorder

/**
 * TLS 配置面板 UI
 */
class TlsConfigPanel(
    private val callbacks: IBurpExtenderCallbacks,
    private val proxyManager: GoProxyManager
) : JPanel() {
    
    private val enabledCheckbox: JCheckBox
    private val fingerprintComboBox: JComboBox<String>
    private val randomizeCheckbox: JCheckBox
    private val statusLabel: JLabel
    private val ja3DisplayArea: JTextArea
    private val customJa3Area: JTextArea
    private val useCustomCheckbox: JCheckBox
    
    // 预定义的 TLS 指纹
    private val predefinedFingerprints = linkedMapOf(
        "random" to FingerprintInfo("Random (随机)", ""),
        "chrome_120" to FingerprintInfo("Chrome 120", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"),
        "chrome_110" to FingerprintInfo("Chrome 110", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"),
        "firefox_120" to FingerprintInfo("Firefox 120", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0"),
        "firefox_110" to FingerprintInfo("Firefox 110", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"),
        "safari_17" to FingerprintInfo("Safari 17", "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"),
        "edge_120" to FingerprintInfo("Edge 120", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"),
        "ios_17" to FingerprintInfo("iOS 17 Safari", "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"),
        "android_chrome" to FingerprintInfo("Android Chrome", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"),
        "curl" to FingerprintInfo("curl/8.x", "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2"),
        "golang" to FingerprintInfo("Go HTTP Client", "771,49200-49196-49192-49188-49172-49162-159-107-57-52393-52392-52394-65413-196-136-129-157-61-53-192-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,0-11-10-35-13-15,29-23-24-25,0"),
        "okhttp" to FingerprintInfo("OkHttp 4.x", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0")
    )
    
    data class FingerprintInfo(val displayName: String, val ja3: String)
    
    init {
        layout = BorderLayout(10, 10)
        border = BorderFactory.createEmptyBorder(15, 15, 15, 15)
        
        // 创建主滚动面板
        val mainPanel = JPanel()
        mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
        
        // ===== 基本设置面板 =====
        val enablePanel = createSectionPanel("基本设置")
        enabledCheckbox = JCheckBox("启用 TLS 指纹伪装", true)
        enabledCheckbox.font = Font(Font.SANS_SERIF, Font.PLAIN, 13)
        enabledCheckbox.addActionListener { updateStatus() }
        enablePanel.add(enabledCheckbox)
        mainPanel.add(enablePanel)
        
        mainPanel.add(Box.createVerticalStrut(10))
        
        // ===== 指纹选择面板 =====
        val fingerprintPanel = createSectionPanel("指纹配置")
        fingerprintPanel.layout = BoxLayout(fingerprintPanel, BoxLayout.Y_AXIS)
        
        // 先初始化自定义 JA3 输入区域（因为后面会引用）
        customJa3Area = JTextArea(3, 50)
        customJa3Area.font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        customJa3Area.lineWrap = true
        customJa3Area.wrapStyleWord = true
        customJa3Area.isEnabled = false
        customJa3Area.text = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
        
        // 先初始化 useCustomCheckbox
        useCustomCheckbox = JCheckBox("使用自定义 JA3 指纹", false)
        
        // 预设指纹选择行
        val presetRow = JPanel(FlowLayout(FlowLayout.LEFT))
        presetRow.add(JLabel("预设指纹:"))
        
        val displayNames = predefinedFingerprints.map { "${it.value.displayName}" }.toTypedArray()
        fingerprintComboBox = JComboBox(displayNames)
        fingerprintComboBox.preferredSize = Dimension(200, 25)
        fingerprintComboBox.addActionListener { 
            updateJa3Display()
            if (!useCustomCheckbox.isSelected) {
                val selectedIndex = fingerprintComboBox.selectedIndex
                val selectedKey = predefinedFingerprints.keys.toList()[selectedIndex]
                val ja3 = predefinedFingerprints[selectedKey]?.ja3 ?: ""
                if (ja3.isNotEmpty()) {
                    customJa3Area.text = ja3
                }
            }
        }
        presetRow.add(fingerprintComboBox)
        
        randomizeCheckbox = JCheckBox("每次请求随机化", false)
        randomizeCheckbox.toolTipText = "每次请求使用不同的随机指纹"
        presetRow.add(randomizeCheckbox)
        fingerprintPanel.add(presetRow)
        
        // 自定义指纹选项
        val customRow = JPanel(FlowLayout(FlowLayout.LEFT))
        useCustomCheckbox.addActionListener { 
            customJa3Area.isEnabled = useCustomCheckbox.isSelected
            fingerprintComboBox.isEnabled = !useCustomCheckbox.isSelected
            updateJa3Display()
        }
        customRow.add(useCustomCheckbox)
        fingerprintPanel.add(customRow)
        
        // 自定义 JA3 输入区域面板
        val customJa3Panel = JPanel(BorderLayout())
        customJa3Panel.border = EmptyBorder(5, 25, 5, 5)
        
        val customLabel = JLabel("自定义 JA3 字符串 (格式: TLSVersion,Ciphers,Extensions,Curves,PointFormats):")
        customLabel.font = Font(Font.SANS_SERIF, Font.PLAIN, 11)
        customJa3Panel.add(customLabel, BorderLayout.NORTH)
        customJa3Panel.add(JScrollPane(customJa3Area), BorderLayout.CENTER)
        
        fingerprintPanel.add(customJa3Panel)
        mainPanel.add(fingerprintPanel)
        
        mainPanel.add(Box.createVerticalStrut(10))
        
        // ===== 当前 JA3 显示面板 =====
        val ja3Panel = createSectionPanel("当前 JA3 指纹")
        ja3Panel.layout = BorderLayout()
        
        ja3DisplayArea = JTextArea(2, 50)
        ja3DisplayArea.font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        ja3DisplayArea.lineWrap = true
        ja3DisplayArea.wrapStyleWord = true
        ja3DisplayArea.isEditable = false
        ja3DisplayArea.background = Color(245, 245, 245)
        ja3Panel.add(JScrollPane(ja3DisplayArea), BorderLayout.CENTER)
        mainPanel.add(ja3Panel)
        
        mainPanel.add(Box.createVerticalStrut(10))
        
        // ===== 代理状态面板 =====
        val statusPanel = createSectionPanel("代理状态")
        val statusRow = JPanel(FlowLayout(FlowLayout.LEFT))
        
        statusLabel = JLabel("初始化中...")
        statusLabel.font = Font(Font.SANS_SERIF, Font.BOLD, 12)
        statusRow.add(statusLabel)
        
        statusRow.add(Box.createHorizontalStrut(20))
        
        val refreshButton = JButton("刷新状态")
        refreshButton.addActionListener { updateStatus() }
        statusRow.add(refreshButton)
        
        val restartButton = JButton("重启代理")
        restartButton.addActionListener { restartProxy() }
        statusRow.add(restartButton)
        
        statusPanel.add(statusRow)
        mainPanel.add(statusPanel)
        
        mainPanel.add(Box.createVerticalStrut(10))
        
        // ===== 使用说明面板 =====
        val infoPanel = createSectionPanel("使用说明")
        infoPanel.layout = BorderLayout()
        
        val infoText = JTextArea("""
本插件通过本地 Go 代理服务器实现 TLS 指纹伪装，可以：

1. 随机化 TLS 指纹 - 每次请求使用不同的随机指纹
2. 模拟浏览器指纹 - 伪装成 Chrome、Firefox、Safari 等
3. 自定义 JA3 指纹 - 输入任意 JA3 字符串
4. 绕过 WAF 检测 - 避免基于 JA3 指纹的封锁

JA3 格式说明：
TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
例如: 771,4865-4866-4867-49195,0-23-65281-10-11,29-23-24,0

工作原理：
- 插件拦截 HTTPS 请求，转发到本地 Go 代理
- Go 代理使用 uTLS 库以指定的 TLS 指纹与目标建立连接
        """.trimIndent())
        infoText.isEditable = false
        infoText.font = Font(Font.SANS_SERIF, Font.PLAIN, 12)
        infoText.background = background
        infoText.border = EmptyBorder(5, 5, 5, 5)
        infoPanel.add(JScrollPane(infoText), BorderLayout.CENTER)
        mainPanel.add(infoPanel)
        
        // 添加到主面板
        val scrollPane = JScrollPane(mainPanel)
        scrollPane.border = null
        scrollPane.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        add(scrollPane, BorderLayout.CENTER)
        
        // 初始化显示
        updateJa3Display()
        updateStatus()
    }
    
    private fun createSectionPanel(title: String): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = BorderFactory.createCompoundBorder(
            TitledBorder(title),
            EmptyBorder(5, 10, 10, 10)
        )
        panel.alignmentX = Component.LEFT_ALIGNMENT
        return panel
    }
    
    private fun updateJa3Display() {
        if (useCustomCheckbox.isSelected) {
            val customJa3 = customJa3Area.text.trim()
            if (customJa3.isNotEmpty()) {
                ja3DisplayArea.text = "自定义: $customJa3"
            } else {
                ja3DisplayArea.text = "请输入自定义 JA3 字符串"
            }
        } else {
            val selectedIndex = fingerprintComboBox.selectedIndex
            val selectedKey = predefinedFingerprints.keys.toList()[selectedIndex]
            val info = predefinedFingerprints[selectedKey]
            
            if (selectedKey == "random") {
                ja3DisplayArea.text = "每次请求将生成随机 JA3 指纹"
            } else {
                ja3DisplayArea.text = "${info?.displayName}: ${info?.ja3}"
            }
        }
    }
    
    private fun updateStatus() {
        val isRunning = proxyManager.isRunning()
        val port = proxyManager.getProxyPort()
        
        if (isRunning) {
            statusLabel.text = "● 代理运行中 (端口: $port)"
            statusLabel.foreground = Color(0, 128, 0)
        } else {
            statusLabel.text = "● 代理未运行"
            statusLabel.foreground = Color(200, 0, 0)
        }
    }
    
    private fun restartProxy() {
        statusLabel.text = "● 正在重启..."
        statusLabel.foreground = Color(200, 150, 0)
        Thread {
            try {
                proxyManager.stop()
                Thread.sleep(1000)
                proxyManager.start()
                SwingUtilities.invokeLater { updateStatus() }
            } catch (e: Exception) {
                SwingUtilities.invokeLater {
                    statusLabel.text = "● 重启失败: ${e.message}"
                    statusLabel.foreground = Color.RED
                }
            }
        }.start()
    }
    
    fun isTlsEnabled(): Boolean = enabledCheckbox.isSelected
    
    fun getSelectedFingerprint(): String {
        if (useCustomCheckbox.isSelected) {
            return "custom:${customJa3Area.text.trim()}"
        }
        
        val selectedIndex = fingerprintComboBox.selectedIndex
        val selectedKey = predefinedFingerprints.keys.toList()[selectedIndex]
        
        return if (selectedKey == "random" && randomizeCheckbox.isSelected) {
            "random_per_request"
        } else {
            selectedKey
        }
    }
    
    fun getCustomJa3(): String = customJa3Area.text.trim()
}

# Burp TLS Fingerprint Randomizer

一个 Burp Suite 扩展插件，用于随机化/伪装 TLS 指纹（JA3），绕过基于 TLS 指纹的 WAF 检测。

## 功能特性

- **TLS 指纹随机化** - 每次请求生成不同的随机 JA3 指纹
- **浏览器指纹模拟** - 伪装成 Chrome、Firefox、Safari、Edge 等主流浏览器
- **自定义 JA3 指纹** - 支持输入任意 JA3 字符串
- **绕过 WAF 检测** - 避免 CloudFlare、Akamai、PerimeterX 等基于 JA3 的封锁

## 架构原理

```
┌─────────────┐      ┌─────────────────┐      ┌──────────────┐
│  Burp Suite │─HTTP─▶│  Go TLS Proxy   │─TLS─▶│ Target Server│
│  Extension  │      │  (uTLS Library) │      │              │
└─────────────┘      └─────────────────┘      └──────────────┘
```

1. Burp 扩展拦截 HTTPS 请求，通过 HTTP 转发到本地 Go 代理
2. Go 代理使用 [uTLS](https://github.com/refraction-networking/utls) 库以指定的 TLS 指纹与目标建立连接
3. 实现 JA3 指纹伪装，绕过 WAF 检测

## 安装

### 方式一：使用预编译版本

1. 从 [Releases](https://github.com/err0l1/burp_tls/releases) 下载 `burp-tls-fingerprint.jar`
2. 在 Burp Suite 中：`Extensions` → `Add` → 选择下载的 JAR 文件

### 方式二：从源码构建

**前置要求：**
- Go 1.21+
- JDK 17+ (或 21)
- Gradle 8.0+

**构建步骤：**

```bash
# 1. 编译 Go 代理
cd go-proxy
go mod tidy
go build -ldflags="-s -w" -o ../src/main/resources/native/tls-proxy.exe .

# 2. 编译 Burp 扩展
cd ..
./gradlew shadowJar

# 输出文件: build/libs/burp-tls-fingerprint-1.0.0.jar
```

## 使用方法

1. 加载扩展后，在 Burp Suite 中会出现 `TLS Fingerprint` 标签页
2. 勾选 **启用 TLS 指纹伪装**
3. 选择指纹类型：
   - **预设指纹** - Chrome、Firefox、Safari 等
   - **自定义指纹** - 输入任意 JA3 字符串
4. 正常使用 Burp 进行测试

## 支持的指纹

| 指纹名称 | 描述 |
|---------|------|
| Random | 完全随机化的 TLS 指纹 |
| Chrome 120/110 | Google Chrome |
| Firefox 120/110 | Mozilla Firefox |
| Safari 17 | Apple Safari |
| Edge 120 | Microsoft Edge |
| iOS 17 | iOS Safari |
| Android Chrome | Android Chrome |
| curl | curl/8.x |
| OkHttp | OkHttp 4.x |

## JA3 指纹格式

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
```

示例：
```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
```

## 项目结构

```
burp_tls/
├── src/main/kotlin/com/burptls/
│   ├── BurpExtender.kt      # Burp 扩展主类
│   ├── TlsConfigPanel.kt    # UI 配置面板
│   └── GoProxyManager.kt    # Go 代理管理器
├── go-proxy/
│   ├── main.go              # Go TLS 代理服务器
│   └── fingerprints.go      # JA3 指纹生成
├── build.gradle.kts         # Gradle 构建配置
└── README.md
```

## 参考项目

- [burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls)
- [uTLS](https://github.com/refraction-networking/utls)
- [Yakit](https://github.com/yaklang/yakit)
- [JA3](https://github.com/salesforce/ja3)

## License

MIT License

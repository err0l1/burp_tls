# Burp TLS Fingerprint Randomizer

一个 Burp Suite 扩展插件，用于随机化/伪装 TLS 指纹（JA3），绕过基于 TLS 指纹的 WAF 检测。

## 功能特性

- **双模式支持** - 透明模式（兼容性好）和指纹伪装模式（自动回退）
- **TLS 指纹随机化** - 每次请求生成不同的随机 JA3 指纹
- **浏览器指纹模拟** - 伪装成 Chrome、Firefox、Safari、Edge 等主流浏览器
- **自定义 JA3 指纹** - 支持输入任意 JA3 字符串
- **绕过 WAF 检测** - 避免 CloudFlare、Akamai 等基于 JA3 的封锁

## 架构原理

```
┌──────────┐      ┌─────────────────┐      ┌──────────────┐
│   Burp   │─────▶│  Go TLS Proxy   │─────▶│ Target Server│
│  Suite   │      │  (uTLS Library) │      │              │
└──────────┘      └─────────────────┘      └──────────────┘
                         │
            ┌────────────┴────────────┐
            │                         │
      透明模式                   指纹伪装模式
   (直接TCP转发)              (uTLS修改指纹)
```

## 安装

### 方式一：使用预编译版本

1. 从 [Releases](https://github.com/err0l1/burp_tls/releases) 下载 `burp-tls-fingerprint.jar`
2. 在 Burp Suite 中：`Extensions` → `Add` → 选择下载的 JAR 文件

### 方式二：从源码构建

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

### 1. 加载扩展
在 Burp Suite 中加载 `burp-tls-fingerprint.jar`

### 2. 配置上游代理（必须）
1. 打开 `Settings` → `Network` → `Connections`
2. 找到 `Upstream proxy servers`，点击 `Add`
3. 填写：
   - **Destination host**: `*`
   - **Proxy host**: `127.0.0.1`
   - **Proxy port**: `18443`
4. 保存配置

### 3. 选择代理模式
- **透明模式**（默认）- 直接转发，兼容所有网站
- **指纹伪装模式** - 修改 TLS 指纹，失败时自动回退到透明模式

### 4. 选择指纹类型
- 预设指纹：Chrome、Firefox、Safari 等
- 自定义指纹：输入任意 JA3 字符串

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

## 项目结构

```
burp_tls/
├── src/main/kotlin/com/burptls/
│   ├── BurpExtender.kt      # Burp 扩展主类
│   ├── TlsConfigPanel.kt    # UI 配置面板
│   └── GoProxyManager.kt    # Go 代理管理器
├── go-proxy/
│   └── main.go              # Go TLS 代理服务器
├── build.gradle.kts
└── README.md
```

## 参考项目

- [burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls)
- [uTLS](https://github.com/refraction-networking/utls)
- [Yakit](https://github.com/yaklang/yakit)

## License

MIT License

plugins {
    kotlin("jvm") version "1.9.22"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.burptls"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Burp Suite Extender API
    implementation("net.portswigger.burp.extender:burp-extender-api:2.3")
    
    // HTTP Client for communicating with Go proxy
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    
    // JSON parsing
    implementation("com.google.code.gson:gson:2.10.1")
    
    // Kotlin standard library
    implementation(kotlin("stdlib"))
    
    // Coroutines for async operations
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
}

tasks {
    shadowJar {
        archiveBaseName.set("burp-tls-fingerprint")
        archiveClassifier.set("")
        archiveVersion.set(version.toString())
        
        manifest {
            attributes(
                "Implementation-Title" to "Burp TLS Fingerprint Randomizer",
                "Implementation-Version" to version
            )
        }
    }
    
    compileKotlin {
        kotlinOptions.jvmTarget = "21"
    }
    
    compileTestKotlin {
        kotlinOptions.jvmTarget = "21"
    }
}

kotlin {
    jvmToolchain(21)
}

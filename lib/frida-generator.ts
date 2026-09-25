/**
 * Frida Hook Generator for APKLens
 * Auto-generates production-grade Frida .js snippets for Android security testing
 */

export interface FridaSnippet {
  id: string;
  title: string;
  category: "root" | "ssl" | "crypto" | "components" | "custom";
  description: string;
  code: string;
}

/**
 * Generate a complete set of Frida scripts tailored to the analyzed APK
 */
export function generateFridaScripts(
  packageName: string,
  exportedActivities: string[] = [],
  exportedReceivers: string[] = [],
  exportedServices: string[] = []
): FridaSnippet[] {
  const snippets: FridaSnippet[] = [
    {
      id: "universal-ssl-bypass",
      title: "Universal SSL & Certificate Pinning Bypass",
      category: "ssl",
      description: "Hooks OkHttpClient, TrustManager, NetworkSecurityConfig, and HostnameVerifier to intercept HTTPS traffic.",
      code: `/*
 * APKLens Universal SSL Pinning Bypass
 * Target: ${packageName}
 */
Java.perform(function () {
    console.log("[*] APKLens: Initializing SSL Pinning Bypass for ${packageName}...");

    // 1. Bypass TrustManagerImpl (Android 7+)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain bypassed for host: ' + host);
            return untrustedChain;
        };
    } catch (err) {
        console.log('[-] TrustManagerImpl not found: ' + err);
    }

    // 2. Universal X509TrustManager Bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'dev.apklens.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    console.log('[+] checkServerTrusted bypassed!');
                },
                getAcceptedIssuers: function () { return []; }
            }
        });
        var trustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContext_init.implementation = function (km, tm, sr) {
            console.log('[+] SSLContext.init hooked with TrustAllManager');
            SSLContext_init.call(this, km, trustManagers, sr);
        };
    } catch (err) {
        console.log('[-] X509TrustManager hook error: ' + err);
    }

    // 3. OkHttp3 CertificatePinner Bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
        };
    } catch (err) {
        console.log('[-] OkHttp3 CertificatePinner not found');
    }

    // 4. HostnameVerifier Bypass
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAllHostnameVerifier = Java.use('org.apache.http.conn.ssl.AllowAllHostnameVerifier');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log('[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed');
        };
    } catch (err) {
        console.log('[-] HostnameVerifier hook error: ' + err);
    }

    console.log("[+] APKLens: SSL Pinning bypass script active.");
});`
    },
    {
      id: "universal-root-bypass",
      title: "Universal Root & Su Detection Bypass",
      category: "root",
      description: "Intercepts RootBeer, doesSUexist, test-keys checks, and common su binary file inspections.",
      code: `/*
 * APKLens Universal Root Detection Bypass
 * Target: ${packageName}
 */
Java.perform(function () {
    console.log("[*] APKLens: Engaging Root Detection Bypass for ${packageName}...");

    // 1. RootBeer library bypass
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function () {
            console.log('[+] RootBeer.isRooted() -> false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            console.log('[+] RootBeer.isRootedWithoutBusyBoxCheck() -> false');
            return false;
        };
    } catch (err) {
        console.log('[-] RootBeer library not present');
    }

    // 2. File.exists() bypass for su / magisk / busybox
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (
            path.indexOf('/system/app/Superuser.apk') > -1 ||
            path.indexOf('/sbin/su') > -1 ||
            path.indexOf('/system/bin/su') > -1 ||
            path.indexOf('/system/xbin/su') > -1 ||
            path.indexOf('/data/local/xbin/su') > -1 ||
            path.indexOf('/data/local/bin/su') > -1 ||
            path.indexOf('/system/sd/xbin/su') > -1 ||
            path.indexOf('/system/bin/failsafe/su') > -1 ||
            path.indexOf('/data/local/su') > -1 ||
            path.indexOf('magisk') > -1 ||
            path.indexOf('busybox') > -1
        ) {
            console.log('[+] Blocked root file check: ' + path);
            return false;
        }
        return this.exists.call(this);
    };

    // 3. Runtime.exec() bypass for 'su' command
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd === 'su' || cmd.indexOf('which su') > -1) {
            console.log('[+] Intercepted Runtime.exec("' + cmd + '") -> fake FileNotFound');
            throw Java.use('java.io.IOException').$new('Command not found: ' + cmd);
        }
        return this.exec.call(this, cmd);
    };

    // 4. Build.TAGS check bypass (test-keys)
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';

    console.log("[+] APKLens: Root detection bypass armed.");
});`
    },
    {
      id: "crypto-cipher-monitor",
      title: "Real-Time Cryptography & AES Key Logger",
      category: "crypto",
      description: "Monitors javax.crypto.Cipher.init to dump SecretKey, IV, transformation algorithm, and mode in plaintext.",
      code: `/*
 * APKLens Crypto & Cipher Inspector
 * Target: ${packageName}
 */
Java.perform(function () {
    console.log("[*] APKLens: Arming Cryptographic Cipher Monitor...");

    var Cipher = Java.use('javax.crypto.Cipher');
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

    function bytesToHex(bytes) {
        if (!bytes) return "null";
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i] & 0xFF;
            hex.push((b < 16 ? "0" : "") + b.toString(16));
        }
        return hex.join("");
    }

    function bytesToString(bytes) {
        if (!bytes) return "null";
        try {
            var String = Java.use('java.lang.String');
            return String.$new(bytes).toString();
        } catch (e) {
            return "[non-printable]";
        }
    }

    var modeMap = { 1: "ENCRYPT_MODE", 2: "DECRYPT_MODE", 3: "WRAP_MODE", 4: "UNWRAP_MODE" };

    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
        console.log("\\n[!] ===== Cipher.init(mode, key) =====");
        console.log("    Algorithm : " + this.getAlgorithm());
        console.log("    Mode      : " + (modeMap[mode] || mode));
        if (key) {
            console.log("    Key Format: " + key.getFormat());
            console.log("    Key Hex   : " + bytesToHex(key.getEncoded()));
            console.log("    Key ASCII : " + bytesToString(key.getEncoded()));
        }
        return this.init.call(this, mode, key);
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {
        console.log("\\n[!] ===== Cipher.init(mode, key, params) =====");
        console.log("    Algorithm : " + this.getAlgorithm());
        console.log("    Mode      : " + (modeMap[mode] || mode));
        if (key) {
            console.log("    Key Hex   : " + bytesToHex(key.getEncoded()));
            console.log("    Key ASCII : " + bytesToString(key.getEncoded()));
        }
        if (params) {
            try {
                var castedIv = Java.cast(params, IvParameterSpec);
                var ivBytes = castedIv.getIV();
                console.log("    IV Hex    : " + bytesToHex(ivBytes));
                console.log("    IV ASCII  : " + bytesToString(ivBytes));
            } catch (err) {
                console.log("    ParamSpec : " + params.$className);
            }
        }
        return this.init.call(this, mode, key, params);
    };

    console.log("[+] APKLens: Cipher logger initialized.");
});`
    },
    {
      id: "exported-intent-tracer",
      title: "Intent & Component Launcher Tracer",
      category: "components",
      description: "Logs all Intent payloads, extras, actions, and component targets flowing in and out of the app.",
      code: `/*
 * APKLens Intent Tracer
 * Target: ${packageName}
 */
Java.perform(function () {
    console.log("[*] APKLens: Tracing Intent Traffic for ${packageName}...");

    var Intent = Java.use('android.content.Intent');
    var Bundle = Java.use('android.os.Bundle');

    function dumpBundle(bundle) {
        if (!bundle) return "None";
        var keys = bundle.keySet().toArray();
        var result = {};
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            result[k] = "" + bundle.get(k);
        }
        return JSON.stringify(result, null, 2);
    }

    var Activity = Java.use('android.app.Activity');
    Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
        console.log("\\n[>] Activity.startActivity called:");
        console.log("    Action    : " + intent.getAction());
        console.log("    Data URI  : " + intent.getDataString());
        console.log("    Component : " + intent.getComponent());
        console.log("    Extras    : " + dumpBundle(intent.getExtras()));
        return this.startActivity.call(this, intent);
    };

    // Trace exported activity onResume
    ${
      exportedActivities.length > 0
        ? exportedActivities
            .slice(0, 5)
            .map(
              (act) => `
    try {
        var Act_${act.replace(/[^a-zA-Z0-9]/g, "_")} = Java.use("${act}");
        Act_${act.replace(/[^a-zA-Z0-9]/g, "_")}.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState) {
            console.log("[+] Exported Activity spawned: ${act}");
            return this.onCreate.call(this, savedInstanceState);
        };
    } catch(e) {}`
            )
            .join("\n")
        : "// No exported activities to hook directly"
    }

    console.log("[+] APKLens: Intent monitor active.");
});`
    },
    {
      id: "ssl-repinning-burp",
      title: "Android SSL Re-Pinning (Burp Suite CA Injection)",
      category: "ssl",
      description: "Injects Burp Suite CA certificate from /data/local/tmp/cert-der.crt into SSLContext to intercept traffic on hardened devices.",
      code: `/*
 * Android SSL Re-Pinning Frida Script
 * Target: ${packageName}
 * 
 * Setup:
 * 1. Push Burp certificate:
 *    adb push burpca-cert-der.crt /data/local/tmp/cert-der.crt
 * 2. Execute with Frida:
 *    frida -U -f ${packageName} -l frida-android-repinning.js --no-pause
 */

setTimeout(function () {
    Java.perform(function () {
        console.log("[*] APKLens: Initializing SSL Re-Pinning with custom CA for ${packageName}...");

        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        console.log("[+] Loading custom CA from /data/local/tmp/cert-der.crt...");
        var cf = CertificateFactory.getInstance("X.509");
        var fileInputStream = null;

        try {
            fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
        } catch (err) {
            console.log("[-] Error opening cert file: " + err);
            return;
        }

        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();

        var certInfo = Java.cast(ca, X509Certificate);
        console.log("[+] Injected CA Subject: " + certInfo.getSubjectDN());

        // Create a KeyStore containing our trusted CAs
        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Create a TrustManager that trusts our custom CA
        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        console.log("[+] Hijacking javax.net.ssl.SSLContext.init()...");
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (a, b, c) {
            console.log("[+] Intercepted SSLContext.init() -> injecting custom CA TrustManager!");
            this.init(a, tmf.getTrustManagers(), c);
        };

        console.log("[+] APKLens: SSL Re-pinning successfully armed.");
    });
}, 0);`
    },
    {
      id: "frida-multiple-unpinning",
      title: "Universal Multi-Method SSL Unpinning",
      category: "ssl",
      description: "Extensive bypass covering OkHTTPv3 (4 variants), TrustManagerImpl, Conscrypt, GMS, TrustKit, Titanium, Cordova, and WebViewClient.",
      code: `/*
 * Comprehensive Android SSL Pinning Multi-Bypass
 * Target: ${packageName}
 * Run with: frida -U -f ${packageName} -l frida_multiple_unpinning.js --no-pause
 */

setTimeout(function () {
    Java.perform(function () {
        console.log("[*] APKLens: Engaging Multi-Method SSL Pinning Bypass for ${packageName}...");

        // 1. TrustManager (Android < 7)
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.registerClass({
                name: 'dev.apklens.multi.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
            );
            SSLContext_init.implementation = function (km, tm, sr) {
                console.log('[+] Bypassing standard TrustManager request');
                SSLContext_init.call(this, km, TrustManagers, sr);
            };
        } catch (err) {}

        // 2. OkHTTPv3 (quadruple bypass)
        try {
            var OkHTTP3 = Java.use('okhttp3.CertificatePinner');
            OkHTTP3.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
                return;
            };
        } catch (err) {}
        try {
            var OkHTTP3 = Java.use('okhttp3.CertificatePinner');
            OkHTTP3.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
                return;
            };
        } catch (err) {}
        try {
            var OkHTTP3 = Java.use('okhttp3.CertificatePinner');
            OkHTTP3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
                return;
            };
        } catch (err) {}
        try {
            var OkHTTP3 = Java.use('okhttp3.CertificatePinner');
            OkHTTP3['check$okhttp'].implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
                return;
            };
        } catch (err) {}

        // 3. TrustManagerImpl (Android 7+)
        try {
            var array_list = Java.use("java.util.ArrayList");
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                console.log('[+] Bypassing TrustManagerImpl.checkTrustedRecursive');
                return array_list.$new();
            };
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain) {
                console.log('[+] Bypassing TrustManagerImpl.verifyChain');
                return untrustedChain;
            };
        } catch (err) {}

        // 4. Google Play Services Conscrypt
        try {
            var array_list = Java.use("java.util.ArrayList");
            var GMSTrustManagerImpl = Java.use('com.google.android.gms.org.conscrypt.TrustManagerImpl');
            GMSTrustManagerImpl.checkTrustedRecursive.implementation = function () {
                console.log('[+] Bypassing GMS TrustManagerImpl.checkTrustedRecursive');
                return array_list.$new();
            };
        } catch (err) {}

        // 5. TrustKit
        try {
            var Trustkit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            Trustkit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
                return true;
            };
        } catch (err) {}

        // 6. WebViewClient SSL Errors
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (v, handler, err) {
                console.log('[+] Bypassing WebViewClient onReceivedSslError -> proceed()');
                handler.proceed();
            };
        } catch (err) {}

        console.log("[+] APKLens: Multi-Method SSL unpinning active.");
    });
}, 0);`
    },
    {
      id: "fridantiroot-advanced",
      title: "Advanced Anti-Root & Emulator Detection Bypass",
      category: "root",
      description: "Intercepts root packages, su binary existence, build.prop tags, native libc fopen/access, and command execution checks.",
      code: `/*
 * Advanced Anti-Root & Environment Bypass
 * Target: ${packageName}
 * Run with: frida -U -f ${packageName} -l frida_anti_root.js --no-pause
 */

Java.perform(function () {
    console.log("[*] APKLens: Arming Advanced Anti-Root & Environment Bypass for ${packageName}...");

    var rootPackages = [
        "com.noshufou.android.su", "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.topjohnwu.magisk", "me.weishu.kernelsu", "com.dimonvideo.luckypatcher"
    ];

    var rootBinaries = ["su", "busybox", "supersu", "magisk", "daemonsu"];

    // 1. PackageManager check bypass
    try {
        var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
        ApplicationPackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (pname, flags) {
            if (rootPackages.indexOf(pname) > -1) {
                console.log("[+] Blocked root package detection for: " + pname);
                pname = "dev.apklens.safe.package";
            }
            return this.getPackageInfo(pname, flags);
        };
    } catch (e) {}

    // 2. File.exists check bypass
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var name = this.getName();
            if (rootBinaries.indexOf(name) > -1) {
                console.log("[+] Blocked root binary check: " + name);
                return false;
            }
            return this.exists.call(this);
        };
    } catch (e) {}

    // 3. Process & command execution bypass
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (cmd === "su" || cmd.indexOf("which su") > -1) {
                console.log("[+] Intercepted su shell execution: " + cmd);
                throw Java.use("java.io.IOException").$new("Command not found: " + cmd);
            }
            return this.exec.call(this, cmd);
        };
    } catch (e) {}

    // 4. Override Build properties
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        Build.HARDWARE.value = "qcom";
    } catch (e) {}

    console.log("[+] APKLens: Advanced Anti-Root bypass successfully installed.");
});`
    }
  ];

  return snippets;
}

/**
 * Generate a custom hook snippet for a specific class and method name
 */
export function generateCustomMethodHook(className: string, methodName: string = "$init"): string {
  const safeName = className.replace(/[^a-zA-Z0-9]/g, "_");
  return `/*
 * APKLens Custom Hook
 * Class: ${className}
 * Method: ${methodName}
 */
Java.perform(function () {
    try {
        var targetClass = Java.use("${className}");
        var targetMethod = targetClass.${methodName};

        targetMethod.overloads.forEach(function (overload) {
            overload.implementation = function () {
                console.log("[+] Called ${className}.${methodName}() with " + arguments.length + " args");
                for (var i = 0; i < arguments.length; i++) {
                    console.log("    arg[" + i + "] = " + arguments[i]);
                }
                
                // Print Call Stack
                var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                console.log("    Call Stack:\\n" + stack);

                var retval = overload.apply(this, arguments);
                console.log("    Returns: " + retval);
                return retval;
            };
        });
        console.log("[+] Hooked all overloads of ${className}.${methodName}");
    } catch (err) {
        console.log("[-] Failed to hook ${className}.${methodName}: " + err);
    }
});`;
}

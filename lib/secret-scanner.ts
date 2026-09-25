/**
 * Pure TypeScript Automated Secret, API Key, and Insecure Crypto Scanner.
 * Audits DEX string tables and decompiled sources for exposed credentials,
 * cloud keys, and insecure cryptographic implementations.
 */

export interface SecretFinding {
  type: string;
  name: string;
  severity: "high" | "medium" | "low" | "critical";
  match: string;
  location?: string;
  description: string;
}

export interface SecurityRule {
  id: string;
  name: string;
  severity: "high" | "medium" | "low" | "critical";
  pattern: RegExp;
  description: string;
  maskMatch?: boolean;
}

export const SECRET_RULES: SecurityRule[] = [
  {
    id: "aws-key",
    name: "AWS Access Key ID",
    severity: "critical",
    pattern: /\b(AKIA[0-9A-Z]{16})\b/,
    description: "Hardcoded AWS Access Key ID found. An attacker can use this to access cloud infrastructure.",
    maskMatch: true,
  },
  {
    id: "google-api-key",
    name: "Google API Key",
    severity: "high",
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    description: "Hardcoded Google API key found. If not restricted by package name, it can be abused.",
    maskMatch: true,
  },
  {
    id: "firebase-url",
    name: "Firebase Database URL",
    severity: "medium",
    pattern: /https?:\/\/([a-z0-9-]+\.firebaseio\.com)/i,
    description: "Firebase Realtime Database endpoint. Verify rules are not set to open read/write.",
    maskMatch: false,
  },
  {
    id: "stripe-key",
    name: "Stripe API Key",
    severity: "critical",
    pattern: /\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,34})\b/,
    description: "Hardcoded Stripe key detected. Secret keys ('sk_live_...') allow full payment API control.",
    maskMatch: true,
  },
  {
    id: "private-key",
    name: "Private Cryptographic Key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    description: "Unencrypted private key found bundled in application code.",
    maskMatch: false,
  },
  {
    id: "slack-token",
    name: "Slack API Token",
    severity: "high",
    pattern: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34})\b/,
    description: "Slack API token exposed in APK binary strings.",
    maskMatch: true,
  },
  {
    id: "slack-webhook",
    name: "Slack Incoming Webhook",
    severity: "medium",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/,
    description: "Slack webhook URL found. Can be used for spamming internal channels.",
    maskMatch: true,
  },
  {
    id: "bearer-token",
    name: "Hardcoded Authorization Token",
    severity: "high",
    pattern: /\bBearer\s+([A-Za-z0-9\-_.]{30,})\b/i,
    description: "Hardcoded static Bearer / JWT token in compiled binary.",
    maskMatch: true,
  },
  {
    id: "insecure-ecb",
    name: "Insecure Cipher Mode (AES/ECB)",
    severity: "high",
    pattern: /AES\/ECB\/(?:PKCS5Padding|NoPadding)/i,
    description: "Electronic Codebook (ECB) mode produces identical ciphertext for identical plaintext blocks.",
    maskMatch: false,
  },
  {
    id: "weak-des",
    name: "Weak DES / 3DES Encryption",
    severity: "high",
    pattern: /\b(?:DES|DESede)\/CBC\//i,
    description: "Legacy DES/3DES cipher detected. Modern applications must use AES-256-GCM.",
    maskMatch: false,
  },
  {
    id: "weak-md5",
    name: "Weak Hash Algorithm (MD5 / SHA-1)",
    severity: "medium",
    pattern: /MessageDigest\.getInstance\(["'](MD5|SHA-1)["']\)/i,
    description: "MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.",
    maskMatch: false,
  },
  {
    id: "hardcoded-ip",
    name: "Internal RFC1918 Private IP Address",
    severity: "low",
    pattern: /\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/,
    description: "Hardcoded internal private IP address detected in binary strings.",
    maskMatch: false,
  },
  {
    id: "openai-api-key",
    name: "OpenAI Secret Key",
    severity: "critical",
    pattern: /\b(sk-(?:proj-)?[A-Za-z0-9_\-]{40,64})\b/,
    description: "Exposed OpenAI API key found. Enables unauthorized LLM inference billing and prompt tampering.",
    maskMatch: true,
  },
  {
    id: "github-token",
    name: "GitHub Personal Access Token",
    severity: "critical",
    pattern: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/,
    description: "Active GitHub PAT exposed in application strings. Threat actors can clone private repos or push malicious commits.",
    maskMatch: true,
  },
  {
    id: "database-uri",
    name: "Database Connection String",
    severity: "critical",
    pattern: /\b((?:postgres|postgresql|mongodb(?:\+srv)?|mysql|redis):\/\/[A-Za-z0-9_]+:[^@\s"']+@[^\s"'<>]{4,})\b/i,
    description: "Hardcoded database URI with embedded authentication credentials.",
    maskMatch: true,
  },
  {
    id: "twilio-credentials",
    name: "Twilio Account SID / Key",
    severity: "high",
    pattern: /\b((?:AC|SK)[a-f0-9]{32})\b/,
    description: "Twilio API identifier. If paired with an auth token, enables SMS toll fraud and telecom hijacking.",
    maskMatch: true,
  },
  {
    id: "sendgrid-key",
    name: "SendGrid API Key",
    severity: "high",
    pattern: /\b(SG\.[a-zA-Z0-9_\-\.]{60,70})\b/,
    description: "SendGrid mailing API key exposed. Allows attackers to send spoofed phishing emails.",
    maskMatch: true,
  },
  {
    id: "dcl-invocation",
    name: "Dynamic Code Loading (DCL)",
    severity: "high",
    pattern: /\b(DexClassLoader|PathClassLoader)\b/,
    description: "Dynamic Dalvik bytecode loading detected. Common vector for dropping encrypted secondary payloads.",
    maskMatch: false,
  },
  {
    id: "runtime-exec",
    name: "Native OS Shell Execution",
    severity: "high",
    pattern: /\bRuntime\.getRuntime\(\)\.exec\b|\bProcessBuilder\b/,
    description: "Direct invocation of Linux shell or external processes. Review for command injection vulnerabilities.",
    maskMatch: false,
  },
  {
    id: "insecure-trustmanager",
    name: "Custom / Insecure TLS TrustManager",
    severity: "critical",
    pattern: /\b(?:TrustAllCerts|NullTrustManager|ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier|checkServerTrusted\s*\(\s*\)\s*\{\s*\})\b/i,
    description: "Disables standard X.509 certificate validation, leaving application vulnerable to man-in-the-middle (MITM) attacks.",
    maskMatch: false,
  },
  {
    id: "static-iv",
    name: "Static / Predictable Initialization Vector (IV)",
    severity: "high",
    pattern: /IvParameterSpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]{1,40}\}|["'](?:00000000|12345678|0123456789abcdef|abcdef9876543210)["'])/i,
    description: "Hardcoded static initialization vector found. Reusing static IVs with CBC/GCM modes destroys cipher confidentiality.",
    maskMatch: false,
  },
  {
    id: "weak-rc4-blowfish",
    name: "Legacy RC4 / Blowfish Cipher",
    severity: "high",
    pattern: /\b(?:RC4|ARCFOUR|Blowfish)\/ECB\b/i,
    description: "Obsolete RC4 or Blowfish stream/block cipher detected. Prone to known keystream biases and plaintext recovery.",
    maskMatch: false,
  },
  {
    id: "insecure-prng",
    name: "Insecure Random Number Generator",
    severity: "medium",
    pattern: /\bnew\s+java\.util\.Random\b/,
    description: "java.util.Random is a linear congruential PRNG and not cryptographically secure. Use java.security.SecureRandom instead.",
    maskMatch: false,
  },
  {
    id: "s3-bucket",
    name: "Amazon AWS S3 Bucket URL",
    severity: "medium",
    pattern: /https?:\/\/([a-z0-9.\-_]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com)\b/i,
    description: "Direct Amazon S3 bucket endpoint exposed. Ensure bucket permissions restrict public read/write access.",
    maskMatch: false,
  },
  {
    id: "jwt-secret",
    name: "Hardcoded JWT Secret / Token",
    severity: "critical",
    pattern: /\b(?:jwt_secret|jwtSecret|JWT_TOKEN)\s*=\s*["']([A-Za-z0-9_\-]{16,})["']/i,
    description: "Hardcoded JSON Web Token secret key detected. Allows forging arbitrary user claims and privilege escalation.",
    maskMatch: true,
  },
];

export function scanForSecrets(strings: string[]): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seenMatches = new Set<string>();

  for (const str of strings) {
    if (!str || str.length < 8) continue;

    for (const rule of SECRET_RULES) {
      const match = str.match(rule.pattern);
      if (match) {
        const rawMatch = match[1] || match[0];
        if (seenMatches.has(rawMatch)) continue;
        seenMatches.add(rawMatch);

        let displayMatch = rawMatch;
        if (rule.maskMatch && rawMatch.length > 8) {
          displayMatch = `${rawMatch.slice(0, 4)}••••••••${rawMatch.slice(-4)}`;
        }

        findings.push({
          type: rule.id,
          name: rule.name,
          severity: rule.severity,
          match: displayMatch,
          description: rule.description,
        });
      }
    }
  }

  return findings;
}

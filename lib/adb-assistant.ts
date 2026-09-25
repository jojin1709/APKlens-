/**
 * ADB Exploit Assistant for APKLens
 * Generates ready-to-run adb commands and bash/batch scripts for Android penetration testing
 */

export interface ComponentRef {
  name: string;
  exported: string | boolean | null;
  authorities?: string;
}

export interface AdbCommandItem {
  id: string;
  category: "activity" | "receiver" | "service" | "provider" | "deeplink" | "backup" | "inspect";
  title: string;
  description: string;
  command: string;
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
}

function isExported(exp: string | boolean | null): boolean {
  return exp === true || exp === "true";
}

export function generateAdbCommands(
  packageName: string,
  activities: ComponentRef[] = [],
  receivers: ComponentRef[] = [],
  services: ComponentRef[] = [],
  providers: ComponentRef[] = [],
  deepLinks: Array<{ uri: string; component?: string }> = [],
  allowBackup: boolean = true
): AdbCommandItem[] {
  const items: AdbCommandItem[] = [];

  // Exported Activities
  activities
    .filter((a) => isExported(a.exported))
    .forEach((act, idx) => {
      const cmpName = act.name.startsWith(".") ? `${packageName}${act.name}` : act.name;
      items.push({
        id: `act-${idx}`,
        category: "activity",
        title: `Launch Exported Activity: ${act.name.split(".").pop()}`,
        description: `Directly invokes this exported activity without authentication or launcher interaction.`,
        command: `adb shell am start -n ${packageName}/${cmpName}`,
        risk: act.name.toLowerCase().includes("admin") || act.name.toLowerCase().includes("auth") || act.name.toLowerCase().includes("secret") ? "HIGH" : "MEDIUM"
      });
    });

  // Exported Broadcast Receivers
  receivers
    .filter((r) => isExported(r.exported))
    .forEach((rec, idx) => {
      const cmpName = rec.name.startsWith(".") ? `${packageName}${rec.name}` : rec.name;
      items.push({
        id: `rec-${idx}`,
        category: "receiver",
        title: `Trigger Broadcast Receiver: ${rec.name.split(".").pop()}`,
        description: `Sends an arbitrary broadcast intent to this unprotected receiver.`,
        command: `adb shell am broadcast -a android.intent.action.MAIN -n ${packageName}/${cmpName}`,
        risk: "HIGH"
      });
    });

  // Exported Services
  services
    .filter((s) => isExported(s.exported))
    .forEach((svc, idx) => {
      const cmpName = svc.name.startsWith(".") ? `${packageName}${svc.name}` : svc.name;
      items.push({
        id: `svc-${idx}`,
        category: "service",
        title: `Start Background Service: ${svc.name.split(".").pop()}`,
        description: `Forcefully instantiates this background service.`,
        command: `adb shell am startservice -n ${packageName}/${cmpName}`,
        risk: "MEDIUM"
      });
    });

  // Exported Content Providers
  providers
    .filter((p) => isExported(p.exported))
    .forEach((prv, idx) => {
      const auth = prv.authorities || packageName;
      items.push({
        id: `prv-${idx}`,
        category: "provider",
        title: `Query Content Provider: ${prv.name.split(".").pop()}`,
        description: `Attempts to read unprotected database records via content resolver URI.`,
        command: `adb shell content query --uri content://${auth}/`,
        risk: "CRITICAL"
      });
    });

  // Deep Links
  deepLinks.forEach((dl, idx) => {
    items.push({
      id: `dl-${idx}`,
      category: "deeplink",
      title: `Trigger Deep Link Intent (${dl.uri})`,
      description: `Tests intent handling, client-side routing, and potential parameter injection.`,
      command: `adb shell am start -W -a android.intent.action.VIEW -d "${dl.uri}" ${packageName}`,
      risk: "MEDIUM"
    });
  });

  // Backup extraction
  if (allowBackup) {
    items.push({
      id: "backup-dump",
      category: "backup",
      title: "Dump App Private Storage (allowBackup=true)",
      description: "Extracts private databases, shared preferences, and files via ADB backup without root.",
      command: `adb backup -f ${packageName}_backup.ab -noapk ${packageName}`,
      risk: "CRITICAL"
    });
    items.push({
      id: "backup-extract",
      category: "backup",
      title: "Unpack ADB Backup to TAR",
      description: "Converts .ab archive into readable directory of app data.",
      command: `dd if=${packageName}_backup.ab bs=24 skip=1 | openssl zlib -d > ${packageName}_backup.tar && tar -xvf ${packageName}_backup.tar`,
      risk: "HIGH"
    });
  }

  // App debug & storage inspect
  items.push({
    id: "run-as-prefs",
    category: "inspect",
    title: "Inspect SharedPreferences via run-as",
    description: "Accesses app sandbox if app is debuggable.",
    command: `adb shell "run-as ${packageName} ls -la /data/data/${packageName}/shared_prefs"`,
    risk: "INFO"
  });

  items.push({
    id: "dumpsys-package",
    category: "inspect",
    title: "Dump Package Permissions & Signatures",
    description: "Displays granted permissions, signatures, and component states.",
    command: `adb shell dumpsys package ${packageName}`,
    risk: "INFO"
  });

  return items;
}

/**
 * Generate a complete bash exploit POC script
 */
export function generateAdbExploitScript(packageName: string, commands: AdbCommandItem[]): string {
  return `#!/usr/bin/env bash
# APKLens Automated ADB Exploit & Audit Script
# Target: ${packageName}
# Generated on: ${new Date().toISOString()}

set -e

echo "[*] Verifying ADB device connection..."
adb get-state || { echo "[-] No Android device detected via ADB"; exit 1; }

echo "[*] Target package: ${packageName}"

${commands
  .map(
    (cmd) => `
echo "--------------------------------------------------"
echo "[+] Testing: ${cmd.title} [${cmd.risk}]"
echo "    CMD: ${cmd.command}"
${cmd.command} || echo "[-] Command exited with error"
sleep 1`
  )
  .join("\n")}

echo "[+] Exploit automation sequence completed."
`;
}

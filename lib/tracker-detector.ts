/**
 * Pure TypeScript Tracker and Analytics Detector based on the Exodus Privacy Signature Catalog.
 * Scans multi-DEX class catalogs and string pools to identify embedded tracking SDKs,
 * advertising frameworks, and telemetry libraries.
 */

export interface TrackerRule {
  id: string;
  name: string;
  category: "Advertising" | "Analytics" | "Crash Reporting" | "Profiling" | "Location" | "Social" | "Utility";
  website: string;
  codeSignatures: RegExp[];
  description: string;
}

export interface MatchedTracker {
  id: string;
  name: string;
  category: "Advertising" | "Analytics" | "Crash Reporting" | "Profiling" | "Location" | "Social" | "Utility";
  website: string;
  description: string;
  matchedClasses: string[];
}

export const EXODUS_TRACKER_RULES: TrackerRule[] = [
  {
    id: "google-admob",
    name: "Google AdMob",
    category: "Advertising",
    website: "https://admob.google.com",
    codeSignatures: [/com\.google\.android\.gms\.ads/i, /com\.google\.ads\./i],
    description: "Mobile advertising network by Google enabling targeted banner, interstitial, and rewarded ads.",
  },
  {
    id: "google-firebase-analytics",
    name: "Google Firebase Analytics",
    category: "Analytics",
    website: "https://firebase.google.com",
    codeSignatures: [/com\.google\.firebase\.analytics/i, /com\.google\.android\.gms\.measurement/i],
    description: "App measurement and user event telemetry solution by Google.",
  },
  {
    id: "facebook-ads",
    name: "Facebook Audience Network",
    category: "Advertising",
    website: "https://www.facebook.com/audiencenetwork",
    codeSignatures: [/com\.facebook\.ads\./i],
    description: "Targeted advertising platform monetizing in-app inventory via Meta profiles.",
  },
  {
    id: "facebook-analytics",
    name: "Facebook Analytics & SDK",
    category: "Analytics",
    website: "https://developers.facebook.com",
    codeSignatures: [/com\.facebook\.appevents\./i, /com\.facebook\.internal\./i],
    description: "Tracks user behavioral conversions, installs, and deep links connected to Facebook profiles.",
  },
  {
    id: "appsflyer",
    name: "AppsFlyer",
    category: "Analytics",
    website: "https://www.appsflyer.com",
    codeSignatures: [/com\.appsflyer\./i],
    description: "Mobile attribution and marketing analytics measuring user acquisition and campaign conversions.",
  },
  {
    id: "adjust",
    name: "Adjust",
    category: "Analytics",
    website: "https://www.adjust.com",
    codeSignatures: [/com\.adjust\.sdk\./i],
    description: "Mobile attribution platform analyzing acquisition channels and user lifetime value.",
  },
  {
    id: "branch",
    name: "Branch Metrics",
    category: "Analytics",
    website: "https://branch.io",
    codeSignatures: [/io\.branch\.referral\./i],
    description: "Deep linking and attribution platform tracking cross-platform referral conversions.",
  },
  {
    id: "mixpanel",
    name: "Mixpanel",
    category: "Analytics",
    website: "https://mixpanel.com",
    codeSignatures: [/com\.mixpanel\.android\./i],
    description: "Product analytics platform tracking user interaction funnels and cohort retention.",
  },
  {
    id: "amplitude",
    name: "Amplitude",
    category: "Analytics",
    website: "https://amplitude.com",
    codeSignatures: [/com\.amplitude\.api\./i],
    description: "Digital optimization and behavioral product analytics system.",
  },
  {
    id: "applovin",
    name: "AppLovin",
    category: "Advertising",
    website: "https://www.applovin.com",
    codeSignatures: [/com\.applovin\./i],
    description: "Mobile gaming advertising and user monetization platform.",
  },
  {
    id: "unity-ads",
    name: "Unity3D Ads",
    category: "Advertising",
    website: "https://unity.com/solutions/unity-ads",
    codeSignatures: [/com\.unity3d\.ads\./i, /com\.unity3d\.services\.ads/i],
    description: "Video advertising network optimized for mobile games and apps.",
  },
  {
    id: "ironsource",
    name: "ironSource",
    category: "Advertising",
    website: "https://www.is.com",
    codeSignatures: [/com\.ironsource\./i],
    description: "App monetization and advertising mediation network.",
  },
  {
    id: "flurry",
    name: "Flurry Analytics",
    category: "Analytics",
    website: "https://www.flurry.com",
    codeSignatures: [/com\.flurry\.android\./i],
    description: "Real-time mobile application usage analytics by Yahoo.",
  },
  {
    id: "sentry",
    name: "Sentry",
    category: "Crash Reporting",
    website: "https://sentry.io",
    codeSignatures: [/io\.sentry\./i],
    description: "Application monitoring and crash diagnostic telemetry reporting platform.",
  },
  {
    id: "bugsnag",
    name: "Bugsnag",
    category: "Crash Reporting",
    website: "https://www.bugsnag.com",
    codeSignatures: [/com\.bugsnag\.android\./i],
    description: "Error monitoring, session tracking, and crash reporting system.",
  },
  {
    id: "onesignal",
    name: "OneSignal",
    category: "Utility",
    website: "https://onesignal.com",
    codeSignatures: [/com\.onesignal\./i],
    description: "Push notifications and customer messaging platform with device analytics.",
  },
  {
    id: "segment",
    name: "Twilio Segment",
    category: "Profiling",
    website: "https://segment.com",
    codeSignatures: [/com\.segment\.analytics\./i],
    description: "Customer Data Platform (CDP) capturing user interactions for downstream routing.",
  },
  {
    id: "braze",
    name: "Braze",
    category: "Profiling",
    website: "https://www.braze.com",
    codeSignatures: [/com\.braze\./i, /com\.appboy\./i],
    description: "Customer engagement and cross-channel user profiling engine.",
  },
  {
    id: "kochava",
    name: "Kochava",
    category: "Analytics",
    website: "https://www.kochava.com",
    codeSignatures: [/com\.kochava\./i],
    description: "Attribution modeling and omnichannel audience profiling tool.",
  },
  {
    id: "clevertap",
    name: "CleverTap",
    category: "Analytics",
    website: "https://clevertap.com",
    codeSignatures: [/com\.clevertap\.android\.sdk\./i],
    description: "Customer lifecycle management and user behavioral analytics platform.",
  },
  {
    id: "instabug",
    name: "Instabug",
    category: "Crash Reporting",
    website: "https://instabug.com",
    codeSignatures: [/com\.instabug\.library\./i],
    description: "In-app bug reporting, crash logging, and performance telemetry.",
  },
  {
    id: "chartboost",
    name: "Chartboost",
    category: "Advertising",
    website: "https://www.chartboost.com",
    codeSignatures: [/com\.chartboost\.sdk\./i],
    description: "Mobile video advertising and interstitial game monetization network.",
  },
];

/**
 * Scan all discovered classes and strings against Exodus tracker patterns.
 */
export function detectTrackers(classes: string[], strings: string[] = []): MatchedTracker[] {
  const matchedMap = new Map<string, MatchedTracker>();
  const combined = [...classes, ...strings.slice(0, 5000)];

  for (const item of combined) {
    if (!item) continue;
    for (const rule of EXODUS_TRACKER_RULES) {
      if (rule.codeSignatures.some((sig) => sig.test(item))) {
        if (!matchedMap.has(rule.id)) {
          matchedMap.set(rule.id, {
            id: rule.id,
            name: rule.name,
            category: rule.category,
            website: rule.website,
            description: rule.description,
            matchedClasses: [],
          });
        }
        const entry = matchedMap.get(rule.id)!;
        if (entry.matchedClasses.length < 5 && !entry.matchedClasses.includes(item)) {
          entry.matchedClasses.push(item);
        }
      }
    }
  }

  return Array.from(matchedMap.values());
}

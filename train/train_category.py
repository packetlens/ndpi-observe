#!/usr/bin/env python3
"""
train_category.py — train RF to classify traffic into BUSINESS-RELEVANT
categories rather than specific apps. Operators (Telnyx, mobile carriers)
need "what KIND of traffic is this?" not "which exact service?".
"""
import sys, os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

FEATURES = [
    "pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max", "pkt_len_total",
    "iat_mean_s", "iat_std_s", "iat_min_s", "iat_max_s",
    "duration_s", "n_pkts", "proto", "dport",
    "first_pkt_len", "last_pkt_len",
]

# Map specific app labels to coarse business-relevant traffic categories.
# Keep categories COARSE — that's the entire point of the exercise.
LABEL_TO_CATEGORY = {
    # Video streaming (large sustained downstream transfers)
    "NetFlix":      "video_streaming",
    "YouTube":      "video_streaming",
    "Twitch":       "video_streaming",
    "TikTok":       "video_streaming",

    # Audio streaming
    "Spotify":      "audio_streaming",

    # Social media (mixed media + API)
    "Facebook":     "social_media",
    "Twitter":      "social_media",
    "Instagram":    "social_media",
    "LinkedIn":     "social_media",
    "Reddit":       "social_media",
    "Pinterest":    "social_media",
    "Tiktok":       "social_media",

    # Search engines (small queries, fast responses)
    "Google":       "search",
    "GoogleServices": "search",
    "Bing":         "search",
    "Duckduckgo":   "search",

    # E-commerce (page loads + product images)
    "Amazon":       "ecommerce",
    "eBay":         "ecommerce",
    "Booking":      "ecommerce",
    "Airbnb":       "ecommerce",
    "AmazonAWS":    "cloud_infra",

    # Developer / SaaS / API endpoints (small bursts, programmatic)
    "Github":       "developer_saas",
    "Githubassets": "developer_saas",
    "Atlassian":    "developer_saas",
    "Microsoft":    "developer_saas",
    "GMail":        "developer_saas",
    "Statuspage":   "developer_saas",
    "Split":        "developer_saas",
    "Datadoghq":    "developer_saas",
    "Apollo":       "developer_saas",
    "Sentry":       "developer_saas",
    "Grafana":      "developer_saas",
    "Outlook":      "developer_saas",

    # Ad tech / analytics (periodic beacons, small)
    "Adsrvr":       "ad_tech",
    "Adnxs":        "ad_tech",
    "Criteo":       "ad_tech",
    "Demdex":       "ad_tech",
    "Mktoresp":     "ad_tech",
    "Demandbase":   "ad_tech",
    "Bizible":      "ad_tech",
    "Scorecardresearch": "ad_tech",
    "Doubleclick":  "ad_tech",

    # Privacy / consent banners
    "Onetrust":     "ad_tech",
    "Cookielaw":    "ad_tech",

    # CDN traffic — could be anything underneath, varies wildly
    "Cloudflare":   "cdn",
    "Akamai":       "cdn",
    "Akamaiedge":   "cdn",
    "Fastly":       "cdn",
    "Fastly-insights": "cdn",
}


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <features.csv>")
        sys.exit(1)

    df = pd.read_csv(sys.argv[1])
    print(f"Total rows: {len(df)}")

    df["category"] = df["label"].map(LABEL_TO_CATEGORY)
    df = df.dropna(subset=["category"]).copy()
    print(f"Rows mapped to categories: {len(df)}")

    counts = df["category"].value_counts()
    print(f"\nCategory distribution:")
    print(counts.to_string())

    # Drop categories with too few samples
    keep = counts[counts >= 30].index.tolist()
    df = df[df["category"].isin(keep)].copy()
    print(f"\nKeeping {len(keep)} categories with >=30 samples ({len(df)} rows)")

    X = df[FEATURES].values.astype(float)
    y = df["category"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print(f"\nTraining RandomForest ({len(X_train)} train, {len(X_test)} test)...")
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=16,
        class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = (y_pred == y_test).mean()
    print(f"\n=== Random Forest accuracy: {acc:.3f} ===\n")
    print(classification_report(y_test, y_pred, zero_division=0))

    print("Top 8 features:")
    for name, imp in sorted(zip(FEATURES, clf.feature_importances_),
                            key=lambda x: -x[1])[:8]:
        print(f"  {name:18s} {imp:.4f}")

    print("\nConfusion matrix (rows=true, cols=pred):")
    classes = sorted(set(y_test))
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    print(f"{'':20s} " + " ".join(f"{c[:10]:>10s}" for c in classes))
    for i, true_cls in enumerate(classes):
        print(f"{true_cls:20s} " + " ".join(f"{cm[i,j]:>10d}" for j in range(len(classes))))


if __name__ == "__main__":
    main()

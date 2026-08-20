# Path A, fully local — tap the real myQ app, 5 devices, only Google is cloud

This is Path A's methodology exactly — **your phone presses the buttons inside
the official myQ app**, so to Chamberlain it's your finger and there is nothing
to detect or block — but rebuilt so the **only** thing that leaves your house
is Google recognizing your sentence. No MacroDroid cloud, no IFTTT, no Nabu
Casa. And it handles all 5 devices by name.

## The problem this solves

Path A's single-device trick ("myQ app launched" → tap) is already 100% local,
but it can't tell "garage door 2" from "gate" — the app opens the same way
every time. The multi-device version I first described fixed that with
MacroDroid's **cloud** webhook. You don't want that cloud. So we need a bridge
that carries *which device you said* from Google down to the right macro on
your phone, using only your LAN.

**The bridge is Home Assistant running on your own network.** Google already
knows how to talk to a local HA instance (free, self-hosted). HA then pokes
your phone locally, and MacroDroid taps the right myQ tile. HA is not opening
anything — it's just the local switchboard that routes "which device" to the
phone.

```
"OK Google, open garage door 2"          ← Google's cloud — the ONLY cloud, only for the words
        ▼
Google Home routine → activates script.open_garage_2 in YOUR Home Assistant
        ▼   (free self-hosted google_assistant integration; Google → your HA URL)
Home Assistant on your LAN runs that script
        ▼   (LAN, no third-party cloud — see the two transport tiers below)
signal lands on your phone carrying "garage door 2"
        ▼
MacroDroid catches it → runs the Garage-Door-2 macro → taps that tile in the myQ app
        ▼
Garage door 2 opens. Path A methodology intact; myQ never bypassed, never told.
```

Everything below the first arrow is on your network. Pick one of two ways for
HA to reach the phone.

---

## Choose your HA→phone transport

### Tier 1 — HA Companion notification (simplest; cloud = Google only)

Home Assistant's official Companion app receives a **notification** from HA;
MacroDroid's *Notification Received* trigger matches it and runs the right
macro. This is a well-worn, reliable pattern.

- The notification is delivered over **Google's FCM** push service. That's
  Google infrastructure — which your rule already allows ("everything local
  except Google"). No *other* cloud is involved: not MacroDroid's, not
  IFTTT's, not Nabu Casa's.
- Zero extra apps beyond HA Companion + MacroDroid, both of which you're
  installing anyway.

Use this unless you specifically object to FCM.

### Tier 2 — local MQTT (purist; cloud = Google voice recognition only)

If you want *nothing at all* to leave the LAN except the voice recognition
itself — not even FCM — use a local MQTT broker:

- Run the **Mosquitto** add-on in HA (a broker on your LAN).
- HA publishes to a per-device topic (`myq/garage2/open`).
- On the phone, a small MQTT client app (**MqttDroid** or **MQTT Client**,
  both free, both integrate with MacroDroid) subscribes to those topics on
  your LAN and fires a MacroDroid trigger when a message arrives.
- Nothing touches the internet after Google hands the intent to HA. Fully LAN.

Slightly more setup (one extra app + broker), but it's the strict-local answer.

Both tiers are **multi-device by construction**: one notification tag / one
MQTT topic per device, so the right macro always runs.

---

## Build it

### 1. Home Assistant on your LAN

Install HA (Raspberry Pi, mini-PC, NAS VM — HA Green/Yellow if you want
appliance-style). This is the local brain; you likely want it anyway.

### 2. Add the bridge config

Drop [`ha-bridge.yaml`](ha-bridge.yaml) into your HA config (as a package, or
paste its sections into `configuration.yaml`). It defines:

- **5 dummy `script` entities** — `open_gate`, `open_garage_1` … `open_garage_4`.
  They control nothing directly; each one just signals your phone. They exist
  so Google has something to "activate."
- Each script's action: **Tier 1** `notify.mobile_app_<yourphone>` with a
  unique tag, **or Tier 2** `mqtt.publish` to a unique topic. Both are in the
  file — enable the block you want.
- The `google_assistant:` exposure block naming the 5 scripts.

Replace `<yourphone>` and the placeholder names, then restart HA.

### 3. Expose the 5 to Google — free, self-hosted

Use HA's **manual `google_assistant` integration** (not Nabu Casa — that's a
paid cloud relay). Google talks straight to your own HA HTTPS endpoint:

- One-time (~1–2 h): GCP project + HomeGraph API + service account, per
  https://www.home-assistant.io/integrations/google_assistant/
- Expose your 5 scripts (Settings → Voice assistants → Expose), nothing else.
- HA must be reachable at an HTTPS URL from the internet — DuckDNS + Let's
  Encrypt (both free HA add-ons) do this. This *is* the Google-half of the
  chain; everything past HA stays on the LAN.

### 4. Build the phone macros

Follow [`macrodroid-multi-device.md`](macrodroid-multi-device.md): one macro
per device, each triggered by its notification tag (Tier 1) or MQTT topic
(Tier 2), each recorded to tap that device's tile **by its name text** in the
myQ app. That's the whole "Path A" part — the accessibility tap on the real
app — unchanged, just triggered locally and per-device.

### 5. Voice commands

In Google Home, one routine per device so your natural phrase maps to the
script:

| You say | Routine action |
|---|---|
| "open the gate" | Activate `Gate` (`script.open_gate`) |
| "open garage door 1" | Activate `Garage Door 1` |
| "open garage door 2" | Activate `Garage Door 2` |
| "open garage door 3" | Activate `Garage Door 3` |
| "open garage door 4" | Activate `Garage Door 4` |

Because each device is its own named HA script, **Google distinguishes them
from your sentence** — no phrase-parsing on the phone, no per-device webhooks
in anybody's cloud.

---

## What's cloud vs local, precisely

| Step | Where it runs |
|---|---|
| Hearing "open garage door 2" + running the routine | Google cloud (unavoidable for Gemini) |
| Routine → your HA | Google → your HA URL over the internet (the Google-half) |
| HA script → phone (Tier 1 FCM / Tier 2 MQTT) | Tier 1: Google FCM. Tier 2: **your LAN only** |
| MacroDroid tapping the myQ app | **your phone** |
| myQ sending "open" to the opener | myQ's normal path (as if you tapped it yourself) |

Tier 2 = the only non-local packet is Google recognizing your words. That's as
local as "OK Google" can ever be.

## Honest caveats (same family as Path A)

- **Phone must be on and unlockable** for the accessibility tap — Android
  blocks taps under a secure lock. Use your in-hand phone, or dedicate an old
  unlocked phone at home as the "presser" (it just needs HA Companion +
  MacroDroid + myQ logged in).
- **myQ in-app passcode/biometric must be off**, or the macro can't reach the
  tile.
- **A myQ redesign** means re-recording the one tap per affected device (~2
  min each). Macros match the tile's **name text**, so minor layout shifts
  survive.
- ~5–10 s end-to-end (myQ cold start dominates). If you later want ~2 s and
  no phone at all, that's the relay path (`../local`-style hardware in
  `../esphome/`), but that bypasses myQ — a different philosophy from Path A.

## Security

You're wiring voice to "open." Keep myQ's own open/close notifications on so
you see every activation, use per-voice matching in Google Home, pick
non-obvious routine phrases, and secure HA (strong password + 2FA — it's
internet-reachable for the Google link). The gate/garage is physical access to
your property; treat the whole chain like a key.

## Files

```
local/
├── README.md                    ← this guide
├── ha-bridge.yaml               ← HA scripts + google_assistant exposure + notify/MQTT (both tiers)
└── macrodroid-multi-device.md   ← per-device tap macro template (notification & MQTT triggers)
```

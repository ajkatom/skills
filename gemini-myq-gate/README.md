# gemini-myq-gate

Say **"OK Google, open the gate"** to your Gemini phone assistant and have a
myQ-controlled gate actually open — even though myQ has no Google/Gemini
integration and Chamberlain has blocked every third-party API.

## Why this kit exists

Chamberlain (myQ's owner) shut down all third-party API access in late 2023 and
has kept closing loopholes since:

| Route | Status |
|---|---|
| Native myQ ↔ Google Home | Discontinued; grandfathered for pre-existing links only |
| IFTTT myQ service | Alive but **cannot open** anything (close/light actions only, by design) |
| Home Assistant / Homebridge myQ integrations | Removed Dec 2023 when the API was blocked; never restored |
| Unofficial API libraries (pymyq, hjdhjd/myq, Python-MyQ, …) | Archived/dead; Chamberlain fingerprints clients and **locks accounts** (3 failed or 10 successful logins per hour triggers a 60-minute lockout) |
| ratgdo / Konnected blaQ | Garage door openers only — do not fit gate operators; newest Security+ firmware blocks them anyway |

So this kit does not fight the API war. It uses the two levers Chamberlain
cannot take away:

1. **The official myQ app on your own phone.** Software path: an Android
   accessibility macro presses the gate button *in the real app* when Gemini
   hears your phrase. Unblockable — to Chamberlain it is literally you tapping.
2. **The gate operator's own wired trigger input.** Hardware path: a $15–20
   Wi-Fi relay wired in parallel with the operator's open input, exposed to
   Google Home natively. myQ keeps working untouched.

## Pick your path

| | Path A — Phone macro | Path B — Dedicated presser phone | Path C — Relay (endgame) |
|---|---|---|---|
| Cost | $0 (MacroDroid free tier is enough) | $0 if you own any old Android | ~$15–25 (Shelly 1 or ESP32+relay) |
| Build time | ~30 min | ~1–2 h | ~1 h + wiring |
| Works from Google/Nest speakers too | Only via the IFTTT variant (A2) | Yes | Yes |
| Reliability | Good (survives myQ app updates if re-recorded) | Very good | Excellent, fully local |
| Touches your gate hardware | No | No | Yes (2 low-voltage wires) |
| Setup docs | [`macrodroid/opengate-macro.md`](macrodroid/opengate-macro.md) | [`home-assistant/`](home-assistant/) | [`esphome/gate-relay.yaml`](esphome/gate-relay.yaml) |

**Recommendation:** build Path A tonight — it proves the whole voice chain
with zero purchases. If you end up using it daily, graduate to Path C for
speed and reliability (2 s instead of ~10 s, no phone required).

---

## Path A — "OK Google, open the gate" → your phone taps the myQ app

### How it works

```
"OK Google, open the gate"
        │  (Gemini executes your Google Home routine)
        ▼
Google Home routine — custom starter: "open the gate"
        │  action: custom command → "Open myQ"
        ▼
myQ app launches on your phone
        │  (MacroDroid trigger: Application Launched = myQ)
        ▼
MacroDroid macro: wait for the app to load → accessibility-tap
the gate control (recorded once with MacroDroid's wizard) → go home
        ▼
Gate opens. myQ app/account totally standard — nothing for Chamberlain to block.
```

### Build it

1. Install **MacroDroid** (Play Store) and build the `OpenGate` macro —
   exact click-by-click steps in
   [`macrodroid/opengate-macro.md`](macrodroid/opengate-macro.md).
2. Create the Google Home routine:
   - Google Home app → **Automations** → **+ New** → **Household** (or Personal).
   - **Starters** → *When I say to Google Assistant* → add
     `open the gate`, `open gate`, `open the front gate`.
   - **Actions** → *Try adding your own* / **Custom action** → type: `Open myQ`.
   - Save. Gemini executes Home routines, so the phrase works whether your
     phone is set to Gemini or classic Assistant.
3. Say **"OK Google, open the gate."** The myQ app pops up and the macro
   presses the button for you.

### Variant A2 — trigger by webhook instead of app-launch (also enables speakers)

The app-launch trigger has one side effect: manually opening the myQ app also
fires the macro (the macro in `macrodroid/opengate-macro.md` ships with a
3-second on-screen cancel window for exactly that). If you want a clean
trigger, or you want the phrase to work on Nest/Google speakers while your
phone sits at home:

1. In the macro, replace the *Application Launched* trigger with
   **Webhook (URL)** — MacroDroid gives you a private URL like
   `https://trigger.macrodroid.com/<your-device-id>/opengate`.
2. In **IFTTT** (free tier is sufficient — this is one applet):
   *If* **Google Assistant V2** "Activate scene" named `Gate`,
   *Then* **Webhooks** "Make a web request" to your MacroDroid URL.
3. IFTTT publishes `Gate` as a **scene** into your Google Home, so
   "OK Google, activate Gate" works everywhere. Wrap it in the same Home
   routine ("open the gate" → custom action `activate Gate`) to keep your
   natural phrase.
4. Add the *Launch myQ + tap* actions after the webhook trigger exactly as in
   the macro doc.

### Honest limitations of Path A

- **The phone must be on and unlockable.** Android will not let an
  accessibility service tap "through" a secure lock screen. In practice this
  doesn't bite: when you say "OK Google…" to your phone you're holding it
  unlocked. For hands-free-while-locked, use A2 with a dedicated home phone
  (Path B) or the relay (Path C).
- **myQ app updates can move the button.** Re-record the single UI Interaction
  action (2 minutes) if the app redesigns. The macro doc pins the click to the
  control's text/description rather than coordinates to survive minor updates.
- **In-app passcode/biometric lock must be off** in myQ settings, or the
  macro can't get past it.
- ~5–10 seconds voice-to-motion (app cold start dominates). Path C is ~2 s.

---

## Path B — dedicated "button presser" phone (+ optional Home Assistant)

Any old Android phone becomes an always-ready gate opener: plugged in at home,
screen lock set to *None* (it only holds the myQ login), myQ + MacroDroid
installed, same macro as Path A but triggered **only** by its private webhook
URL.

- Minimal version: IFTTT scene → webhook → old phone (exactly A2, but the
  macro runs on the spare phone, so your daily phone's lock state is
  irrelevant and any speaker in the house works).
- Home Assistant version (no IFTTT, free, and gives you a real `Gate` device
  in Google Home with your own PIN policy): see
  [`home-assistant/README.md`](home-assistant/README.md) for the
  `rest_command` + script + Google Assistant exposure config.

Security note for the spare phone: it has no lock screen, so treat it like a
gate remote — it *is* one. Keep it inside the house; enable Android's
Find/Wipe on it.

---

## Path C — the endgame: a relay in parallel with the gate operator (~$20)

LiftMaster/Chamberlain gate operators (LA400/LA412/LA500, CSW24U/CSL24U, …)
expose low-voltage **dry-contact input terminals** for keypads, exit loops and
open/cycle buttons. A Wi-Fi relay pulsed across those terminals is
indistinguishable from a wired button press. myQ never knows it's there.

Two ways to build it:

- **No-code:** Shelly 1 (Gen3/Gen4 or Plus 1 UL). Power it from the
  operator's accessory 12/24 V terminals, wire its dry contacts to the
  open/cycle input, set output mode to *momentary/auto-off 0.5 s*, link
  Shelly Cloud in Google Home (*Works with Google → Shelly*). Name it `Gate`.
- **DIY/local-first:** ESP32 + relay board flashed with
  [`esphome/gate-relay.yaml`](esphome/gate-relay.yaml) — includes the
  momentary pulse, an optional magnetic reed sensor so Google can answer
  "is the gate open?", and Home Assistant native discovery. Expose it to
  Google via Nabu Casa or the manual (free) Google Assistant integration.

Can't or don't want to wire at the operator? **Remote hack:** solder the
relay contacts across the button of a spare gate remote, power the pair by
USB anywhere in Wi-Fi + RF range. Works with any gate brand, zero wiring at
the gate.

### Making the phrase natural (applies to B and C)

Google exposes the relay as a *switch*, so the literal phrase is "turn on the
Gate". Fix with a Home routine: starter `open the gate` → action
`turn on Gate`. Alternatively set the device type to **Gate/Garage** in
Google Home — you'll get Google's spoken-PIN security challenge before it
opens (safer, slightly slower).

---

## Security — read this once

Whatever path you pick, you are deliberately removing a safety gate (pun
intended) that myQ and Google put in front of "open":

- Anyone who can talk to your phone/speakers can open the gate. Consider a
  less-guessable phrase, per-voice match in Google Home, or the Gate device
  type + PIN on Path C.
- The MacroDroid webhook URL and IFTTT applet are bearer secrets — treat them
  like keys, don't share screenshots containing them.
- A relay bypasses myQ's alerts for *that* trigger; keep the myQ app's
  open/close notifications on (the gate's own sensor still reports state).

## Repo contents

```
gemini-myq-gate/
├── README.md                     ← you are here (decision tree + Paths A/B/C)
├── macrodroid/
│   └── opengate-macro.md         ← click-by-click macro build (Path A / A2 / B)
├── home-assistant/
│   ├── README.md                 ← spare-phone bridge via HA, Google exposure
│   └── gate.yaml                 ← rest_command / script / google_assistant config
└── esphome/
    └── gate-relay.yaml           ← ESP32 relay firmware for Path C
```

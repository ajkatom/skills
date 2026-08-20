# Path B — spare Android phone as gate bridge, fronted by Home Assistant

Use this when you want:

- the phrase to work on **every Google/Nest speaker and any phone** in the
  household, hands-free, regardless of your daily phone's lock state;
- a real `Gate` entity in Google Home (state, routines, PIN policy);
- no IFTTT dependency.

## Architecture

```
"OK Google, open the gate"        (any Gemini device / Nest speaker)
        ▼
Google Home  ──►  Home Assistant cloud link (Nabu Casa, or free manual setup)
        ▼
script.gate_open  (exposed to Google as switch/scene "Gate")
        ▼
rest_command.gate_phone_tap  ──►  MacroDroid webhook URL
        ▼
Spare Android phone (plugged in at home, no secure lock,
myQ app + the OpenGate macro from ../macrodroid/opengate-macro.md
with the Webhook trigger variant)
        ▼
Accessibility tap on the official myQ app → gate opens
```

The spare phone is the only component that talks to myQ, and it does so
through the official app — nothing for Chamberlain to detect or block.

## Setup

1. **Spare phone:** install myQ (logged in, in-app lock off), MacroDroid, and
   build the macro from [`../macrodroid/opengate-macro.md`](../macrodroid/opengate-macro.md)
   using the **Webhook (URL)** trigger + a first action of *Launch
   Application: myQ*. Screen lock: None/Swipe. Battery optimization off for
   both apps. Keep it on a charger.
2. **Home Assistant:** merge [`gate.yaml`](gate.yaml) into your config
   (package-style: drop it in `packages/` with `homeassistant: packages: !include_dir_named packages`),
   replace the webhook placeholder, restart.
3. **Google exposure**, either:
   - **Nabu Casa** (paid, 2 clicks): Settings → Voice assistants → expose
     `script.gate_open` to Google Assistant; or
   - **Manual Google Assistant integration** (free, ~30 min once): follow
     https://www.home-assistant.io/integrations/google_assistant/ — create a
     GCP project, enable HomeGraph API, add the `google_assistant:` block from
     `gate.yaml`, link "[test] your project" in the Google Home app.
4. In Google Home the script appears as `Gate`. Add a routine:
   starter `open the gate` → action `activate Gate` (scripts surface as
   scene-like entities; adjust wording to what Google Home shows).

## Why a script and not a cover/switch?

A momentary "press the button" is what we actually have — a script models
that honestly and never shows a misleading on/off state. If you later add a
gate position sensor (reed switch on Path C hardware), switch to a template
cover and expose open/close/state properly.

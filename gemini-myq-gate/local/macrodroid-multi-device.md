# MacroDroid — one tap-macro per device, triggered locally

You build one macro per opener. They're identical except for (a) what triggers
them and (b) which myQ tile they tap. This is the Path A accessibility tap —
unchanged — just fired by a local signal from Home Assistant and told which
device to press.

Build the first one fully, then use MacroDroid's **Export/Clone macro** and
edit the two differing bits for the rest.

## One-time setup (same as base Path A)

- Install **MacroDroid** and the **Home Assistant Companion** app; log the
  Companion app into your local HA.
- Grant MacroDroid: **Accessibility service**, **Display over other apps**,
  and set **battery optimization = unrestricted** for MacroDroid *and* myQ
  (Samsung/Xiaomi: also remove them from "sleeping apps").
- In **myQ**: turn **off** any in-app passcode/biometric lock.
- Notifications from HA Companion must be **allowed** (and put them on a
  dedicated "myQ" channel — the config sets `channel: myQ` — so they don't get
  throttled or hidden).

## The macro — `OpenGarage2` (example)

### Trigger — pick the tier you chose in HA

**Tier 1 (HA Companion notification):**
- **Device Events → Notification → Received Notification**
  - Application: **Home Assistant**
  - Content / "Text matches": `MYQ_OPEN_GD2` (the `message` from the script)
  - Tip: match on the unique token, not the whole string, so it's robust.

**Tier 2 (local MQTT):**
- Install **MqttDroid** or **MQTT Client**, point it at your Mosquitto broker
  on the LAN, subscribe to `myq/gd2/open`.
- Configure that app to fire a MacroDroid trigger on message — either it can
  broadcast an intent (**MacroDroid trigger: Device Events → Intent Received**)
  or post a local notification MacroDroid matches (same as Tier 1). Both apps
  document a MacroDroid hand-off; use whichever the app version exposes.

### Actions (identical for every device except the tap)

1. **Screen → Keep Device Awake** → *screen on*, 45 s.
2. **Applications → Launch Application → myQ.**
3. **Logic → Wait Before Next Action** → 4 s (myQ cold start + device list;
   raise to 6–8 s on a slow phone/connection).
4. **Device Actions → UI Interaction → Click** — **record this, don't type it:**
   - Choose **Identify by clicking**, open myQ to the screen with the tiles,
     tap MacroDroid's capture notification, then tap **Garage Door 2's** open
     control.
   - When MacroDroid asks how to identify the element, prefer **text /
     content-description = "Garage Door 2"** over "exact location", so the tap
     follows the tile if the layout shifts.
   - If your tiles don't all fit on screen, add a **UI Interaction → Gesture
     (swipe up)** before the click so the target scrolls into view.
   - If myQ shows a confirm/slide step to open, record a **second** UI
     Interaction (or a Gesture for a slider).
5. **Logic → Wait** → 3 s (let the command send).
6. *(optional)* **Press Home Button**; **Keep Device Awake → Disable.**

### Clone for the other four

Export/clone the macro; in each copy change only:
- the **trigger's match text / MQTT topic** (`MYQ_OPEN_GATE`, `MYQ_OPEN_GD1`,
  `MYQ_OPEN_GD3`, `MYQ_OPEN_GD4`), and
- the **recorded tap** (re-record on that device's tile: `Gate`,
  `Garage Door 1`, `Garage Door 3`, `Garage Door 4`).

That's it — 5 macros, no phrase parsing on the phone. HA already told each
macro exactly which device to press.

## Test ladder

1. In HA, run `script.open_garage_2` manually (Developer Tools → Actions).
   The notification/MQTT message should fire the macro and open door 2. Tune
   the step-3 wait until the tap reliably lands after the tile renders.
2. Say **"OK Google, open garage door 2."** Full chain end to end.
3. Repeat for each device; confirm each phrase opens only its own door.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Macro doesn't fire on the notification | Confirm the trigger app is exactly "Home Assistant" and the match text is the token only; check the myQ notification channel isn't blocked; battery = unrestricted. |
| Wrong door taps after a myQ update | Re-record that macro's UI Interaction (it pins to tile text, so usually just a re-capture). |
| Fires when phone is locked → nothing happens | Expected (Android blocks accessibility under a secure lock). Use the phone in hand, or a dedicated unlocked "presser" phone at home. |
| Notification is delayed | Doze throttling — the config sends `ttl:0, priority:high`; also unrestrict battery for HA Companion. Tier 2 (MQTT) avoids FCM delivery variance entirely. |
| myQ shows login screen sometimes | Session expired — log in once; disable any "log out on inactivity" option. |

## Dedicated "presser" phone (recommended for hands-free / locked use)

An old Android at home on a charger, screen lock **None**, running HA Companion
+ MacroDroid + myQ (logged in), with all 5 macros. Now any phrase from any
Nest speaker → Google → HA → this phone taps myQ, regardless of where your
daily phone is or whether it's locked. Treat that phone like a gate remote —
it is one — and keep it inside the house.

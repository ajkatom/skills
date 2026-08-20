# OpenGate — MacroDroid macro, click by click

Goal: when the myQ app launches (because your "open the gate" routine told
Gemini to open it), MacroDroid waits for the app to load and presses the gate
control for you — using Android's accessibility service, i.e. a genuine tap
inside the official app.

MacroDroid's free tier (5 macros) is enough. Tested approach on Android 10+.

## 0. One-time permissions

Install MacroDroid, open it, and grant when prompted (Settings → MacroDroid):

- **Accessibility service** (MacroDroid UI Interaction) — required for the tap.
- **Display over other apps** — required for the cancel overlay.
- **Battery optimization: unrestricted** for MacroDroid *and* for myQ, or
  Android will freeze either app mid-macro (Settings → Apps → … → Battery).

In the **myQ app**: Settings → Security → make sure any in-app
passcode/biometric lock is **off** (the macro cannot pass it).

## 1. Create the macro

MacroDroid home → **Add Macro**. Name it `OpenGate`.

### Trigger

- **Applications → Application Launched → myQ**
  - "Application launched" detection method: leave default (Accessibility).

*(Variant A2 / Path B: use **Connectivity → Webhook (URL)** instead, identifier
`opengate`. MacroDroid shows your private URL —
`https://trigger.macrodroid.com/<device-id>/opengate`. Anything that GETs that
URL runs the macro; wire it to an IFTTT Google Assistant V2 scene as described
in the main README. With the webhook trigger, add an action
**Applications → Launch Application → myQ** as the first action below, since
the app is no longer what triggered us.)*

### Actions — add in this order

1. **Screen → Keep Device Awake** → *Enable (screen on)*, duration 45 seconds.
2. **MacroDroid Specific → Set Variable** → create local boolean `cancelled` = `false`.
3. **Notifications → Display Notification (overlay style: "Screen overlay")**
   — text: `Opening gate in 3s — tap to CANCEL`.
   - Configure "on click" to set `cancelled = true` (use the notification
     action option *Run macro actions on click* → Set Variable `cancelled = true`).
   - If your MacroDroid version lacks click-actions on overlays, use
     **MacroDroid Specific → Confirm Next Actions** with a 3 s auto-confirm
     instead — same effect, one dialog.
4. **Logic → Wait Before Next Action** → 3 seconds.
5. **Logic → If** → condition: variable `cancelled = true` → **Exit Macro**;
   **End If**.
6. **Logic → Wait Before Next Action** → 4 seconds (myQ cold start + device
   list load; raise to 6–8 s on a slow phone or slow connection).
7. **Device Actions → UI Interaction → Click** — *this is the important one,
   record it, don't type it:*
   - Choose **Identify by clicking**. MacroDroid posts a persistent
     notification: *"Interact with the screen to configure"*.
   - Open the myQ app manually, get to the screen showing your **gate tile**,
     pull down the shade, tap MacroDroid's notification, then tap the gate's
     open control exactly as you normally would.
   - MacroDroid captures the element (view ID / text / content description —
     prefer **content description or view ID** over "exact location" so the
     macro survives layout shifts).
   - If myQ asks for a second tap to confirm opening (some firmware/regions
     show a *"Confirm"* or slide control), add a **second UI Interaction**
     action recorded the same way. For a slide/hold control use
     **UI Interaction → Gesture** and record the swipe.
8. **Logic → Wait Before Next Action** → 3 seconds (let the command fire).
9. *(optional)* **Device Actions → Press Home Button**, and
   **Screen → Keep Device Awake → Disable**.

### Constraints (optional but sensible)

- none required. If you chose the *Application Launched* trigger and you also
  open myQ manually sometimes, the 3-second cancel overlay in steps 2–5 is
  your safety net — tap it and nothing happens.

## 2. Test ladder

1. Run the macro manually from MacroDroid (▶ button) with the phone unlocked
   → gate should open. Adjust the step-6 wait until the tap lands reliably
   *after* the tile renders.
2. Open the myQ app by hand → overlay appears → tap cancel → nothing happens.
3. Full chain: **"OK Google, open the gate"** → routine opens myQ → macro
   taps → gate opens.

## 3. Known failure modes & fixes

| Symptom | Fix |
|---|---|
| Tap fires on the wrong thing after a myQ app update | Re-record the UI Interaction action (2 min). |
| Macro doesn't run when phone is locked | Expected — Android blocks accessibility taps under a secure lock. Say the phrase to the phone in hand, or use a dedicated unlocked spare phone (Path B), or the relay (Path C). |
| myQ shows the login screen occasionally | myQ session expired. Log in once; consider unchecking any "log out on inactivity" style option. |
| Macro randomly stops triggering after a few days | Re-check battery optimization = unrestricted for MacroDroid; some OEMs (Samsung "sleeping apps", Xiaomi) re-enable it — whitelist MacroDroid there too. |
| Routine says "myQ isn't set up" | In the routine, the custom action must be plain text `Open myQ` (it's an Assistant command, not an app picker). |

## Tasker equivalent (if you prefer Tasker)

Same architecture: Profile → Event → *App Opened: myQ* (or an HTTP-triggered
task via Tasker's remote plugin / TaskerNet). Actions: Turn Screen On → Wait
4 s → **AutoInput → Action** (record the click with AutoInput's *UI Query* /
Easy Setup on the gate control) → Wait → Go Home. AutoInput (~$4) is required
for the tap; MacroDroid does it free, which is why it's the primary
recommendation here.

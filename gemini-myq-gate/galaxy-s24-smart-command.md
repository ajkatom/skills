# Galaxy S24 Ultra — custom wake word, one smart command, presses myQ, works anywhere

Exactly what you asked for:

- **Your own activation word** (not "OK Google", not "Hi Bixby") — e.g. say
  **"Sesame, open garage door 2."**
- **One smart command** — a single flow hears the whole sentence, figures out
  which of your 5 openers you named, and opens it. No five separate routines.
- **Presses the real myQ app** (Path A) — so myQ never gets bypassed.
- **Works remotely** — it runs on the phone in your hand, and myQ's own app
  reaches the gate over Chamberlain's cloud from anywhere. No home hub, no LAN,
  no MacroDroid/IFTTT cloud.

## Why this stack (and why not Bixby/Gemini)

A truly **custom** wake word is the catch: Google is locked to "Hey Google",
Bixby to "Hi Bixby" — neither lets you invent a word. The one Android
combination that gives you a custom hotword **and** hands the full spoken
phrase to an automation **and** can tap inside another app is:

| App | Role | Cost |
|---|---|---|
| **Tasker** | the brain: parse the phrase, open myQ, orchestrate | ~$3.49 (7-day free trial) |
| **AutoVoice** | your custom hotword + speech-to-text → Tasker | ~$2.49 (trial); free "lite" covers this use |
| **AutoInput** | taps the myQ tile by its on-screen name | ~$1.99 (trial) |

All three are by joaoapps and designed to work together. (If you'd rather not
buy three apps, there's a Bixby-based fallback at the end — it works, but the
wake word stays "Hi Bixby.")

## How it flows

```
"Sesame, open garage door 2"     (anywhere — home, car, out of town)
      │  AutoVoice hears your custom hotword "Sesame", captures the rest
      ▼
Tasker task: read "garage door 2" from the phrase → set target tile = "Garage Door 2"
      ▼
Tasker opens the myQ app → waits for it to load
      ▼
AutoInput taps the tile whose text = "Garage Door 2"     ← Path A press
      ▼
myQ sends "open" to the opener over its cloud → door 2 opens
```

---

## Build it

### 0. One-time permissions (Settings)

- Install **Tasker**, **AutoVoice**, **AutoInput**.
- Grant **Accessibility** to Tasker/AutoInput (needed for the tap).
- Battery: set **Tasker, AutoVoice, AutoInput and myQ** to **Unrestricted**
  (Settings → Apps → each → Battery). On the S24: also open **Settings →
  Battery → Background usage limits** and make sure none of them are in
  "Sleeping/Deep sleeping apps."
- Grant AutoVoice the **Microphone** permission (and "allow all the time").
- In **myQ**: turn **off** any in-app passcode/biometric lock.

### 1. AutoVoice — your custom activation word

1. Open **AutoVoice → Continuous**. Enable continuous recognition (it keeps a
   quiet persistent notification and listens for your hotword).
2. Set the **hotword / activation phrase** to your word, e.g. `Sesame`
   (pick something distinctive that won't come up in normal speech).
3. Enable **"strip hotword"** (or the equivalent "cut command") so the text
   passed on is just the part after your word (`open garage door 2`).
4. Choose the recognizer: Google's on-device speech is fine and fast; leave
   defaults unless recognition is poor.

> Note on always-listening: continuous hotword detection uses the mic in the
> background and costs some battery. If you'd rather not run it all day, use
> the **Bixby fallback** below (wake with "Hi Bixby") and keep everything else
> the same — or trigger AutoVoice recognition from a home-screen icon / side-key
> gesture instead of a spoken hotword.

### 2. Tasker — the one smart command

Create one **Task** called `OpenMyQ`:

1. **Variable Set** `%phrase` to `%avcommnofilter` (the recognized text),
   lower-cased. (Tasker: `Variable Convert %phrase → To Lower Case`.)
2. **Parse the device** — a short If/Else ladder mapping words to the exact
   tile name in your myQ app. Handle digits *and* words:

   ```
   If %phrase ~ *gate*                     → %tile = Gate
   Else If %phrase ~ *garage*door*1* / *one*   → %tile = Garage Door 1
   Else If %phrase ~ *garage*door*2* / *two*   → %tile = Garage Door 2
   Else If %phrase ~ *garage*door*3* / *three* → %tile = Garage Door 3
   Else If %phrase ~ *garage*door*4* / *four*  → %tile = Garage Door 4
   Else → Flash "Didn't catch which door"; Stop
   End If
   ```
   (Use Tasker "If" actions with the `~` *matches* operator and `*` wildcards.
   Set `%tile` to match your tiles' EXACT text as shown in myQ.)

3. **Launch App** → myQ.
4. **Wait** 4 seconds (raise to 6–8 on a slow start).
5. **AutoInput Action**:
   - Type: **Click**
   - Target: **Text** = `%tile`
   - (This clicks the tile/open control whose visible text matches the device.)
   - If your tiles don't all fit on screen, precede this with an **AutoInput
     Action → Gesture: scroll down** so the target is visible.
6. If myQ shows a **confirm/slide to open**, add a second **AutoInput Action**
   (Click the confirm, or Gesture for a slider).
7. Optional: **Wait** 3 s → **Go Home**.

### 3. Tasker — link the voice to the task

Create a **Profile**:

- **Event → Plugin → AutoVoice Recognized** (or **AutoVoice → Continuous**
  event if you used continuous mode). In its config, set the command filter to
  catch anything after your hotword (leave the filter empty / use a wildcard so
  any "open …" phrase passes).
- Link the profile to the **`OpenMyQ`** task.

That's the whole thing: one profile, one task, five tiles handled by the parse
step. Add a sixth opener later by adding one line to the If-ladder.

---

## Test ladder

1. Run `OpenMyQ` manually in Tasker with `%avcommnofilter` faked to
   `open garage door 2` (Tasker → run task with a set variable) → door 2 opens.
   Tune the step-4 wait until the tap reliably lands after the tile renders.
2. Say **"Sesame, open the gate."** Confirm AutoVoice fires and the gate opens.
3. Run through all 5 phrases; confirm each opens only its own device.
4. Test from **cellular / away from home Wi-Fi** to confirm remote works
   (it will — myQ's app is doing the long haul).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Hotword not heard / stops after a while | Battery unrestricted for AutoVoice; keep it out of "sleeping apps"; make sure the persistent notification is allowed. Continuous recognition is the flaky part — the Bixby fallback avoids it. |
| Recognizes the word but taps nothing | AutoInput needs Accessibility ON; re-check `%tile` matches the tile's exact text; add a scroll before the click. |
| Taps the wrong door after a myQ update | Re-check the tile text; the click targets text, so usually just the label changed. |
| Fires while phone is locked → nothing | Expected — Android blocks accessibility under a secure lock. You're holding the phone to speak, so it's unlocked; fine. |
| myQ shows login screen sometimes | Session expired; log in once and disable any auto-logout option. |
| "one/two" misheard as digits or vice-versa | The If-ladder handles both word and digit forms — keep both patterns per door. |

## Bixby fallback (no third-party apps, wake word = "Hi Bixby")

If you don't want to buy Tasker/AutoVoice/AutoInput or run an always-on mic:

1. **Settings → Modes and Routines → Routines → +**.
2. **If** → **Bixby** voice command → phrase e.g. `open garage door 2`.
3. **Then** → **Open app** myQ, and add the tap. Samsung Routines can't always
   record an in-app tap directly, so the reliable version is: **Then → run a
   MacroDroid macro** (build the 5 tap-macros from
   [`local/macrodroid-multi-device.md`](local/macrodroid-multi-device.md), each
   triggered by a MacroDroid "Modes and Routines"/shortcut hook).
4. One Routine per device (5 total). Wake with **"Hi Bixby, open garage door 2."**

Trade-off vs the Tasker build: wake word is fixed to "Hi Bixby", and it's five
routines instead of one smart command — but zero paid apps and no background
mic. Everything else (remote via myQ cloud, pressing the real app) is the same.

## Security

Voice-to-open now works from anywhere, so: enable **AutoVoice/Bixby voice
match** to your voice, pick a non-obvious activation word, keep myQ's own
open/close push notifications ON so every activation is visible, and keep the
phone itself locked when not in use — it can now open your gate from any
location.

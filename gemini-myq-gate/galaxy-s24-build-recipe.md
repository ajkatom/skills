# Galaxy S24 Ultra — exact build recipe (verified logic)

This is the click-by-click to stand up the "custom wake word + one smart
command" flow, using the **pre-tested** parser so you don't hand-build the
fragile part.

- The decision logic (phrase → which myQ tile) is validated by an automated
  test: `tests/test_parse_command.py` (33/33) and the identical JavaScript in
  `tools/tasker_parse.js` (22/22). You paste that JS as one Tasker action.
- Everything else is standard, documented Tasker/AutoVoice/AutoInput actions.

Tiles it targets today: **Gate, Garage Door 1, Garage Door 2, Garage Door 3**
(the 5th is a one-line add later).

---

## Apps & permissions (once)

1. Install **Tasker**, **AutoVoice**, **AutoInput** (all joaoapps; free trials).
2. **Accessibility ON** for Tasker and AutoInput (Settings → Accessibility →
   Installed apps).
3. **Battery = Unrestricted** for Tasker, AutoVoice, AutoInput, myQ
   (Settings → Apps → each → Battery). Also Settings → Battery → **Background
   usage limits** → ensure none are listed as Sleeping/Deep-sleeping.
4. **Microphone**: allow AutoVoice "all the time."
5. In **myQ**: turn OFF any in-app passcode/biometric lock.

## Part 1 — AutoVoice custom wake word

1. AutoVoice → **Continuous** → enable.
2. Set your **activation phrase** (hotword), e.g. `Sesame`.
3. Enable **strip/cut hotword** so only the words after it are passed on.
4. Leave the recognizer on Google on-device (fast). Keep the persistent
   notification enabled (it's what keeps listening alive).

## Part 2 — the Tasker task `OpenMyQ`

Tasker → **Tasks** tab → **+** → name `OpenMyQ`. Add these actions in order:

**A1 — Variable Set**
- Name: `%phrase`
- To: `%avcommnofilter`
  (the recognized text from AutoVoice; if empty in testing, use `%avcomm`)

**A2 — Code → JavaScriptlet**  ← the verified parser, one action
- Paste the entire contents of [`tools/tasker_parse.js`](tools/tasker_parse.js).
- In the JavaScriptlet's **Variable Names** field, enter: `tile,matched`
  (so `%tile` and `%matched` come back to Tasker).
- Leave Auto Exit ON, timeout default.

**A3 — If** `%matched ~ 0`   (didn't understand)
- **A4 — Flash**: `Didn't catch which door — try again`
- **A5 — Stop**
- **A6 — End If**

**A7 — Launch App** → **myQ**

**A8 — Wait** → **4 seconds**  (bump to 6–8 if myQ is slow to draw the tiles)

**A9 — AutoInput Action**  (the Path A press)
- Configure → **Action**: `Click`
- **Type**: `Text`
- **Value**: `%tile`
- (This taps the tile/open control whose visible text equals the parsed name.)
- If your tiles don't all fit on one screen, add BEFORE this an **AutoInput
  Action → Gesture → Scroll** (down) so the target is visible.

**A10 — (only if myQ shows a confirm/slide to open)**
- A second **AutoInput Action**: Click the confirm button, or **Gesture** to
  perform the slide.

**A11 — Wait** 3 seconds → **A12 — Go Home** (optional tidy-up).

## Part 3 — wire voice → task

Tasker → **Profiles** → **+** → **Event → Plugin → AutoVoice Recognized**
(or **AutoVoice → Continuous** event if that's what you enabled).
- In its config, leave the command filter empty / wildcard so any phrase after
  the hotword passes through.
- When Tasker asks which task to link → choose **`OpenMyQ`**.

Done. One profile, one task, all four doors handled by A2.

---

## Test it on the phone (in this order — safest first)

1. **Dry-run the parser (no door moves):** temporarily disable A7–A12 (long-
   press → Disable). Run `OpenMyQ` from Tasker with A1 set to a literal, e.g.
   change A1 to `%phrase` = `open garage door 2`, run, and Flash `%tile`
   (add a temporary Flash `%tile` after A2). Confirm it shows `Garage Door 2`.
   Try `open the gate`, `door 3`, and a nonsense phrase (should Flash the
   "didn't catch" message). This mirrors the automated test you already saw
   pass — now on your device.
2. **Re-enable A7–A12.** Run `OpenMyQ` manually with A1 back to
   `%avcommnofilter` — but first set A1 to a literal `open garage door 3` once
   more and confirm door 3 (and only door 3) opens. Tune the A8 wait until the
   tap lands reliably after the tiles render.
3. **Voice, at home:** say **"Sesame, open the gate."** Confirm end to end.
4. **Voice, away:** on cellular / off your home Wi-Fi, say a command. It works
   because myQ's own app carries it — no hub or LAN involved.

## Adding the 5th opener later

Two one-line edits, both already staged for you:
- `tools/tasker_parse.js` → add `4: "Garage Door 4"` (its exact myQ name) to
  `KNOWN_DOORS`, and re-paste into A2.
- `tools/parse_command.py` → uncomment the matching line, then rerun
  `python3 tests/test_parse_command.py` to re-verify.

## If a step misbehaves

See the troubleshooting table in
[`galaxy-s24-smart-command.md`](galaxy-s24-smart-command.md). Most common:
AutoInput needs Accessibility ON; `%tile` must equal the tile's EXACT visible
text; and continuous hotword detection needs battery unrestricted.

## No-paid-apps alternative

Prefer not to buy the three apps / run an always-on mic? The Bixby
Modes-and-Routines fallback (wake word "Hi Bixby", one routine per door) is in
[`galaxy-s24-smart-command.md`](galaxy-s24-smart-command.md#bixby-fallback).

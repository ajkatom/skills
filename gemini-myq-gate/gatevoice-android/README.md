# GateVoice — one app, fully offline, presses myQ

A single Android app that replaces Tasker + AutoVoice + AutoInput. It listens
for your command **fully offline** (Vosk — no Google, no cloud), works out
which of Gate / Garage Door 1–3 you said (the parser verified in
`../tools/parse_command.py`, re-checked by a unit test on every build), then
**opens the official myQ app and taps that tile itself** via an Accessibility
service. Because myQ's own app carries the command, it works from anywhere.

Two ways to trigger, both built in:
- **Custom wake word** (always-on, offline): say e.g. "Sesame, open the gate."
- **One tap**: a Quick Settings tile or a home-screen widget → speak the door.

## Honest status

- The app **builds into an installable APK** via CI (GitHub Actions), which
  also runs the parser unit test. That part is verified.
- What can't be verified without your phone + your myQ app: the exact tap on
  your myQ screen and wake-word accuracy. Those are **tuned on-device** using
  the app's built-in test screen (dry-run the parser; "Open …" buttons show a
  live status like `clicked node for "Gate"` / `gave up finding …`). Expect a
  small tweak or two (the `Tap window` and, if myQ uses odd labels, the tile
  names / a scroll).

## Get the APK

1. Push this folder (already on branch `claude/gemini-myq-gate-control-yo7f2d`).
2. GitHub → **Actions** → **Build GateVoice APK** → run it (or it runs on push).
3. Open the finished run → **Artifacts** → download **GateVoice-debug-apk** →
   unzip to get `app-debug.apk`.
4. Copy it to the phone and install (allow "install unknown apps" for your
   browser/Files app when prompted).

Prefer to build locally? Install Android Studio (or the SDK + JDK 17), then in
this folder:
```
curl -L -o model.zip https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip
unzip -q model.zip && rm -rf app/src/main/assets/model-en-us && mv vosk-model-small-en-us-0.15 app/src/main/assets/model-en-us
gradle :app:assembleDebug     # or ./gradlew if you generate the wrapper
```
APK lands in `app/build/outputs/apk/debug/app-debug.apk`.

## First-run setup on the phone

Open **GateVoice**:

1. **Permissions** — tap *Grant Microphone*, *Grant Notifications*, then
   *Open Accessibility settings* and enable **GateVoice** (this is what lets it
   tap myQ).
2. **Settings** — set your **wake word**, confirm the **Gate** and door tile
   names match myQ exactly (defaults: Gate, Garage Door 1–3), leave `myQ
   package` as-is unless yours differs, **Save**.
3. **Battery** (One UI kills background apps): Settings → Apps → GateVoice →
   Battery → **Unrestricted**; also Settings → Battery → Background usage
   limits → make sure GateVoice and myQ aren't in Sleeping/Deep-sleeping.
4. Turn on **Always listen for wake word** if you want hands-free.

## Test ladder (safe → live)

1. **Dry-run the parser** (no doors move): section 4 — type "open garage door
   2", tap *Parse* → should read `would tap: Garage Door 2`. Try "open the
   gate", "door 3", nonsense. This mirrors the automated test, on your phone.
2. **Open one door**: section 5 — tap *Open Garage Door 3*. Watch it launch
   myQ and tap. Hit *Refresh status* to see what the accessibility service did.
   If it says "gave up finding…", tell me the exact tile label/screen and we
   adjust (usually the tile name or adding a scroll).
3. **One-tap**: add the Quick Settings tile (edit your QS panel → drag in
   *Open Gate*) or the widget; tap it and say a door.
4. **Wake word, at home**, then **from cellular/away** — confirm remote works.

## Add the 5th opener later

In the app's **Doors** field add `;4=<exact myQ name>` and Save. (Also add
`4 to "…"` in `../tools/parse_command.py` and rerun its test to keep the
reference in sync.)

## Layout

```
gatevoice-android/
├── app/src/main/java/com/gatevoice/app/
│   ├── CommandParser.kt          verified phrase → tile logic
│   ├── GateController.kt         parse → launch myQ → arm the tap
│   ├── MyqAccessibilityService.kt  finds & taps the tile (text/desc/gesture)
│   ├── VoskWakeService.kt        always-on offline wake word
│   ├── ListenActivity.kt         one-shot listen (tile/widget)
│   ├── GateTileService.kt        Quick Settings tile
│   ├── GateWidgetProvider.kt     home-screen widget
│   ├── MainActivity.kt           setup + on-device test screen
│   └── Prefs.kt / PendingTap.kt / VoskModelHolder.kt
├── app/src/test/java/…/CommandParserTest.kt   runs in CI
└── (assets/model-en-us fetched at build time)
```

## Security

It opens your gate from voice, anywhere. Use a distinctive wake word, keep
myQ's own open/close notifications on, and keep the phone locked when idle —
GateVoice can open the gate whenever it's unlocked and listening.

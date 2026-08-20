# No hub, works remotely, presses the myQ app — Path A for 5 devices

Your refined requirements: **(1)** the voice trigger doesn't have to be Google,
**(2)** it must work when you're **away from home** (not just on your LAN), and
**(3)** it must keep Path A's logic — **your phone presses the real myQ app**.

There's a clean answer that satisfies all three and drops Home Assistant
entirely.

## The unlock: let your own phone be the "presser"

The myQ app already controls your gate **from anywhere** — that's its whole
job; it talks to Chamberlain's cloud, which talks to the opener. So if the
phone doing the tapping is **the phone in your hand**, remote operation is
automatic:

```
you (anywhere, on cellular or any Wi-Fi)
   │  say your command to the phone's voice assistant
   ▼
a per-device macro on THAT phone opens myQ and taps the right tile   ← Path A, unchanged
   ▼
myQ's own app sends "open" to the gate over Chamberlain's cloud       ← how myQ always works
   ▼
gate opens
```

Why this nails every requirement:

- **Remote:** nothing depends on your home LAN. myQ's cloud is the long-haul
  link, exactly as when you open the gate by hand in the app. Works on
  cellular, hotel Wi-Fi, anywhere.
- **No hub, no relay:** no Home Assistant, no MacroDroid cloud webhook, no
  IFTTT, no MQTT broker. Everything is on the one phone.
- **Multi-device is trivial:** there's no network hop that has to carry "which
  device," so you don't need a bridge. You just make **5 macros on the phone**,
  one per opener, and **5 voice commands**, one per macro. Each phrase → its
  own macro → taps its own tile.
- **Path A intact:** the phone presses the official myQ app. To Chamberlain
  it's your finger. Nothing to detect or block.

The only clouds in the whole chain are **myQ's** (you can't avoid it — the gate
is myQ-controlled no matter what) and your **voice assistant's speech
recognition**. That's the irreducible minimum.

## The 5 macros (same on any phone)

Build these once in MacroDroid (free) — see
[`macrodroid/opengate-macro.md`](macrodroid/opengate-macro.md) for the detailed
click-by-click; the multi-device tap-by-tile-name technique and clone workflow
are in [`local/macrodroid-multi-device.md`](local/macrodroid-multi-device.md).
Each macro:

1. Launch **myQ**.
2. Wait ~4 s for it to load.
3. **UI Interaction → Click**, recorded on that device's tile, identified by
   its **name text** (`Gate`, `Garage Door 1`…`4`) so it survives layout shifts.
4. (If myQ shows a confirm/slide) a second recorded tap/gesture.

The only difference between the 5 macros is which tile they tap — and which
voice command triggers them (next section).

## The voice front-end — pick by your phone

This is the one part that differs by device. All of these run the trigger on
the phone itself, so all of them work remotely (the assistant's recognition may
use its own cloud, but the *action* is local to your phone):

| Your phone | Best voice layer | How it maps phrase → the right macro |
|---|---|---|
| **Samsung Galaxy** | **Modes & Routines** (+ Bixby voice) — native, reliable | A Routine per phrase; trigger = "Bixby voice command" = your exact phrase; action = run that device's MacroDroid macro (or open myQ + tap). Fully on-device. |
| **Pixel / other Android** | **Google/Gemini** routine per device **or** a dedicated voice app | Gemini: one routine per phrase → open the myQ app; distinguish devices via the per-macro technique below. Or use an offline voice-command app that fires a specific MacroDroid macro. |
| **Any Android, want zero Google** | **MacroDroid home-screen voice shortcut** / a lightweight voice-trigger app | Each macro gets a shortcut; a voice app or the assistant "opens" the matching shortcut. |

The cleanest single-command option (works on most phones): a voice layer that
can **pass the whole phrase to one macro** (e.g. Tasker+AutoVoice, or Samsung
Routines with a wildcard). Then ONE flow reads "garage door 2" out of the
phrase, opens myQ, and taps that tile — no need for five separate routines.
AutoVoice's Google Assistant hook is degraded since Google closed third-party
Assistant access, but AutoVoice works well with **Amazon Alexa** and has its
own natural-language recognizer, if you want a non-Google path.

## Optional: away-phone stays home, you're the one remote

If you'd rather the *tapping* phone stay at home (e.g. an old spare) and still
trigger it from anywhere, you'd need an internet relay to reach it — which
reintroduces a cloud (push service, or a small self-hosted endpoint). The
in-hand-phone design above avoids that entirely, which is why it's the
recommendation. Only go the away-phone route if you specifically can't run
myQ on the phone you carry.

## Honest caveats (unchanged from Path A)

- The tapping phone must be **on and unlockable** when the macro runs —
  Android blocks accessibility taps under a secure lock. Since you're speaking
  to the phone in your hand, it's unlocked; fine in practice.
- **myQ's in-app passcode/biometric lock must be off**, or the macro can't
  reach the tile.
- A **myQ redesign** means re-recording the one affected tap (~2 min); macros
  match tile **name text**, so minor updates survive.
- ~5–10 s end to end (myQ cold start dominates).

## Security

You're wiring voice to "open," now usable from anywhere: use a per-voice match
so only you trigger it, pick non-obvious phrases, keep myQ's own open/close
notifications on so every activation is visible, and lock down the phone
itself (it now opens your gate from any location).

## Where this sits among the paths

- This doc = **Path A, hub-free, remote, multi-device** — the best fit for
  "press the app, no Home Assistant, works away from home."
- [`local/README.md`](local/README.md) = Path A but with a home Home Assistant
  bridge (LAN-centric; only if you later add HA).
- [`outside-the-box.md`](outside-the-box.md) = drop myQ entirely (call-to-open
  relay, RF clone) — different philosophy, not "press the app."

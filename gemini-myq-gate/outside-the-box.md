# Outside the box — four angles that don't play myQ's game at all

Paths A–C in the main README still fight on myQ's turf (its app) or the
operator's turf (its wiring). These four sidestep the whole problem by
attacking it from a direction Chamberlain has no control over. The first one
is, honestly, the best idea in this whole kit.

---

## ★ Angle 1 — the phone-call trick: "Hey Google, call Gate"

**The trick:** Google's single most bulletproof, never-deprecated, works-on-
every-device, works-while-locked voice action is *placing a phone call*. So
make "open the gate" a phone call.

A **GSM/4G "dial-to-open" gate relay** (e.g. King Pigeon RTU5024, ~$40, or its
4G sibling) holds a whitelist of caller IDs. When a whitelisted number rings
it, it **rejects the call and pulses its relay** — so the call is free (never
answered) and the gate opens. These are a mature, standalone product category
for exactly this purpose.

```
"Hey Google, call Gate"        ← native Google/Gemini action, any device, phone locked
        ▼
Google places a call to the contact "Gate" (the SIM's number)
        ▼
RTU5024 sees your whitelisted caller ID → rejects the call (free) → pulses relay
        ▼
Relay wired across the operator's open/cycle input → gate opens
```

**Why this is the winner:**
- No app automation, no accessibility service, no MacroDroid to break on a myQ
  update. "Call a contact" has worked identically for a decade and survives
  the Assistant→Gemini transition.
- Works **hands-free while your phone is locked**, and from **any** Nest/Google
  speaker in the house — none of Path A's caveats.
- Completely independent of myQ/Chamberlain. Nothing to detect, nothing to block.
- The device itself does time-of-day access rules and up to hundreds of
  authorized callers if you want family access.

**Build:**
1. Put a cheap IoT/pay-as-you-go SIM in the RTU5024 (a few $/year; needs
   signal at the gate — check bars, add the external antenna if marginal).
2. SMS it your phone number as an authorized caller (manual command, e.g.
   `pwdA001#<yourphone>#`).
3. Wire its relay (NO/COM) across the operator's open/cycle terminals — the
   same pair Path C uses.
4. Save the SIM's number as a contact named **Gate** in your phone.
5. Say **"Hey Google, call Gate."** Google dials, the box rejects+opens.
6. Natural phrasing: add a Google Home routine, starter `open the gate` →
   action `call Gate`, so you never say the word "call."

**Trade-offs:** needs cellular coverage at the gate and a SIM; the call
approach can't tell you gate state (pair with a reed sensor on Path C hardware
if you want status). Anyone whose caller ID you whitelist can open it, and
caller ID *can* be spoofed by a determined attacker — fine for a residential
gate, think twice for high-security sites.

### Angle 1b — no new hardware if you already built Path C

Already have the ESP32/Shelly relay + Home Assistant from Path C? Skip the GSM
box: point a **Google Voice or Twilio number** at a webhook that hits your
relay. "Hey Google, call Gate" → Google Voice/Twilio → webhook → relay. Same
bulletproof voice action, reuses hardware you already own.

---

## ★ Angle 2 — clone the remote's radio, touch nothing

myQ, the operator's wiring, the app — all irrelevant if you just **transmit the
same RF the handheld remote does.** LiftMaster/Chamberlain use the *Security+*
/ *Security+ 2.0* rolling-code protocol, and it has been fully reverse-
engineered and open-sourced (`argilo/secplus`). A **$5 CC1101 radio on an
ESP32** can encode and send a valid rolling code the operator accepts — after
you enroll it once via the operator's LEARN button, exactly like pairing a new
remote.

```
"OK Google, open the gate"
        ▼  (Home Assistant / ESPHome switch, exposed to Google)
ESP32 + CC1101 transmits a Security+ 2.0 rolling code (secplus)
        ▼
Gate operator's own radio receiver accepts it → gate opens
```

**Why it's outside the box:** zero wiring to the operator's control board, zero
myQ involvement, no phone automation. It is a *smart remote* that Google can
press. Genuinely wireless, sits anywhere in RF range.

**Reality check (be honest with yourself before buying parts):**
- This is the most advanced build here — flashing firmware, a CC1101 wired to
  the ESP32's SPI pins, matching your operator's frequency (310/315/390 MHz
  depending on model), and getting the rolling-code counter enrolled.
- Rolling code means you must persist and increment the counter across reboots
  (the reference projects handle this). If the ESP falls far behind, re-enroll.
- Only worth it if wiring at the operator is impossible (gate far from the
  board, sealed commercial operator) and you enjoy the RF hacking. For most
  people Path C's wired relay is simpler and just as invisible to myQ.

Starting points: `github.com/argilo/secplus` (protocol),
`github.com/danscofield/mqqt-secplus-cc1101` (ESP32-S3 + CC1101 transmitter),
and the `openers` project for Security+ 2.0 specifics.

---

## Angle 3 — the best "open gate" command is no command at all

Reframe the request. You don't actually want to *say* "open the gate" every
day — you want the gate open when you arrive. Voice is the fallback for the
edge cases.

- **Geofence auto-open:** Home Assistant (or the Shelly app) fires the relay
  when your phone's location crosses a small radius around home, gated by
  "only if approaching" + "only after 4 pm" + presence conditions so it never
  opens randomly. Pairs with any relay path.
- **Bluetooth/UWB presence:** an ESP32 running ESPHome's `bluetooth_proxy`
  detects your phone/watch/car tag at the driveway and pulses the relay —
  local, no cloud, no cellular.
- **License-plate trigger:** a cheap camera + Frigate/CodeProject.AI reads your
  plate and opens for known vehicles. Overkill for a home, unbeatable for a
  shared driveway.

Keep any voice path from Angle 1/2 or Paths A–C as the manual override for
guests and exceptions. This is what "premium" gate installs actually do —
you're just doing it for ~$40 instead of $$$$.

---

## Angle 4 — grab-bag of levers people forget

- **NFC tag by the door / in the car:** a $0.20 sticker that runs the same
  webhook (via your phone's built-in NFC). Tap to open — faster than talking.
- **Wear OS / watch:** a single complication or Assistant on the watch runs
  the routine; open the gate from your wrist mid-jog.
- **Car integration:** Android Auto runs Google routines; "open the gate" works
  from the head unit. Or program the operator's frequency into the car's
  built-in HomeLink buttons (no phone at all).
- **A physical button that isn't at the gate:** a Shelly Button / Flic by the
  front door hitting the same relay/webhook — for when voice recognition is
  having a bad day.
- **SMS instead of a call:** the same GSM relay opens on a whitelisted SMS
  keyword too; "Hey Google, send a text to Gate saying open" is a native
  action if you'd rather not use the call path.

---

## How to choose

| You want… | Build |
|---|---|
| The most reliable hands-free voice open, minimal fuss | **Angle 1** (GSM call relay) |
| It to work from every speaker with zero phone dependence | **Angle 1** or Path C + Angle 3 |
| Nothing wired to the operator, and you like RF hacking | **Angle 2** (CC1101 clone) |
| To stop saying it entirely | **Angle 3** (presence) + any relay |
| $0 tonight, proof of concept | Path A (main README) |

My pick for most people: **Angle 1**. It's the cheapest path to a *robust*
whole-house "OK Google, open the gate" that doesn't rot the next time an app
updates — because it rides Google's most stable voice action and a dumb,
purpose-built relay, with myQ completely out of the loop.

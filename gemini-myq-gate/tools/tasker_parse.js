// Tasker JavaScriptlet: parse the spoken myQ command into the exact tile name.
//
// HOW IT RUNS ON THE PHONE (Tasker action "Code > JavaScriptlet"):
//   * Tasker exposes the recognized speech as the global `phrase` (you set
//     Tasker var %phrase = %avcommnofilter just before this action; Tasker
//     lowercase-named vars are visible to JS by their bare name).
//   * This script sets `tile` (the exact myQ tile to tap) and `matched`
//     ("1"/"0"). Add them to the JavaScriptlet's "Variable Names" field as
//     tile,matched so Tasker imports them back as %tile and %matched.
//
// Keep this in sync with tools/parse_command.py (same contract, same cases).
// This exact file is executed by the Node test below, so what you paste is
// what was verified.

/* global phrase */
var KNOWN_DOORS = { 1: "Garage Door 1", 2: "Garage Door 2", 3: "Garage Door 3" };
// When the 5th opener exists, add e.g.  4: "Garage Door 4"  above.
var GATE_TILE = "Gate";

var NUMBER_WORDS = {
  "1":1,"one":1,"won":1,
  "2":2,"two":2,"too":2,"to":2,
  "3":3,"three":3,"tree":3,
  "4":4,"four":4,"for":4,"fore":4,
  "5":5,"five":5
};
var DOOR_CUES = ["door","garage","garge","garaje"];
var GATE_CUES = ["gate","gates"];

function parse(text) {
  if (!text) return null;
  var p = String(text).toLowerCase().replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim();
  var tokens = p.split(" ");
  // 1) Gate first
  for (var i = 0; i < GATE_CUES.length; i++) if (p.indexOf(GATE_CUES[i]) !== -1) return GATE_TILE;
  // 2) Garage door N: need a door cue AND a known number
  var hasDoor = false;
  for (var j = 0; j < DOOR_CUES.length; j++) if (p.indexOf(DOOR_CUES[j]) !== -1) hasDoor = true;
  if (hasDoor) {
    for (var k = 0; k < tokens.length; k++) {
      var n = NUMBER_WORDS[tokens[k]];
      if (n && KNOWN_DOORS[n]) return KNOWN_DOORS[n];
    }
  }
  return null;
}

// --- Tasker entry point (uses the global `phrase`) -------------------------
// When run inside Tasker, `phrase` is defined; guard so Node can require this.
if (typeof phrase !== "undefined") {
  var result = parse(phrase);         // eslint-disable-line no-unused-vars
  var tile = result === null ? "" : result;      // -> %tile
  var matched = result === null ? "0" : "1";     // -> %matched
}

// Export for the Node test harness only (Tasker ignores this).
if (typeof module !== "undefined") module.exports = { parse: parse };

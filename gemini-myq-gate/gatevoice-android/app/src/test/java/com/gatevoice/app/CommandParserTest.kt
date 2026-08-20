package com.gatevoice.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Re-verifies the on-device parser against the same cases proven in
 * tools/parse_command.py and tools/tasker_parse.js. Runs in CI on every build,
 * so the APK can never ship logic that diverges from the tested reference.
 */
class CommandParserTest {

    private val gate = "Gate"
    private val gd1 = "Garage Door 1"
    private val gd2 = "Garage Door 2"
    private val gd3 = "Garage Door 3"

    private val cases: List<Pair<String, String?>> = listOf(
        // canonical
        "open the gate" to gate,
        "open garage door 1" to gd1,
        "open garage door 2" to gd2,
        "open garage door 3" to gd3,
        // wake word left in
        "sesame open the gate" to gate,
        "sesame open garage door 2" to gd2,
        // natural variations
        "gate" to gate,
        "open gate please" to gate,
        "garage door one" to gd1,
        "garage door two" to gd2,
        "garage door three" to gd3,
        "open door 3" to gd3,
        "door one" to gd1,
        "open garage 2" to gd2,
        "please open garage door number two" to gd2,
        "can you open the gate" to gate,
        "OPEN GARAGE DOOR 1" to gd1,
        "Open Garage Door 3." to gd3,
        // speech-to-text mishears
        "open garage door too" to gd2,
        "open garage door to" to gd2,
        "open garage door tree" to gd3,
        "open garge door one" to gd1,
        "open garaje door 3" to gd3,
        // negatives -> null (never opens a door)
        "" to null,
        "what's the weather" to null,
        "open the front door" to null,
        "open garage door 4" to null,   // 5th not installed yet
        "garage door four" to null,
        "open garage door 9" to null,
        "turn on the lights" to null,
        "open something" to null,
    )

    @Test
    fun allCasesMatchReference() {
        for ((phrase, expected) in cases) {
            assertEquals("phrase=\"$phrase\"", expected, CommandParser.parse(phrase))
        }
    }

    @Test
    fun gateNeverConfusedWithGarage() {
        assertEquals(gd1, CommandParser.parse("open garage door 1"))
        assertEquals(gd2, CommandParser.parse("garage door 2"))
        assertEquals(gd3, CommandParser.parse("garage door three"))
    }

    @Test
    fun unknownNeverOpensADoor() {
        listOf("open garage door 4", "front door", "hello", "").forEach {
            assertNull(CommandParser.parse(it))
        }
    }

    @Test
    fun multipleDevicesAllReturnedInOrder() {
        assertEquals(listOf(gd2, gate), CommandParser.parseAll("open garage door 2 and gate"))
        assertEquals(listOf(gate, gd2), CommandParser.parseAll("open the gate and garage door 2"))
        assertEquals(listOf(gd1, gd3), CommandParser.parseAll("open garage door 1 and 3"))
        assertEquals(listOf(gd1, gd2, gd3), CommandParser.parseAll("garage door 1 2 3"))
    }

    @Test
    fun parseAllDeduplicates() {
        assertEquals(listOf(gate), CommandParser.parseAll("gate gate"))
        assertEquals(listOf(gd2), CommandParser.parseAll("garage door 2 door two"))
    }

    @Test
    fun parseAllEmptyForUnknown() {
        listOf("", "hello", "open garage door 4").forEach {
            assertEquals(emptyList<String>(), CommandParser.parseAll(it))
        }
    }

    @Test
    fun detectsCloseVsOpen() {
        assertEquals(GateAction.CLOSE, CommandParser.detectAction("close the gate"))
        assertEquals(GateAction.CLOSE, CommandParser.detectAction("shut garage door 2"))
        assertEquals(GateAction.CLOSE, CommandParser.detectAction("close garage door 1 and gate"))
        assertEquals(GateAction.OPEN, CommandParser.detectAction("open the gate"))
        assertEquals(GateAction.OPEN, CommandParser.detectAction("garage door 3"))  // bare -> open
        assertEquals(GateAction.OPEN, CommandParser.detectAction(""))
    }
}

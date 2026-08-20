package com.gatevoice.app

/**
 * Turns recognized speech into the exact myQ tile to tap.
 *
 * This is a direct port of the logic verified by:
 *   - tools/parse_command.py         (33/33)
 *   - tools/tasker_parse.js          (22/22)
 * and re-verified here by CommandParserTest (runs in CI on every build).
 *
 * Contract:
 *   - case-insensitive
 *   - "gate" is checked FIRST so "garage" can't be misread as gate
 *   - a garage door needs a door/garage cue AND a known number
 *   - unknown input returns null -> the app asks again, never opens a wrong door
 */
object CommandParser {

    // Exact tile text as shown in the myQ app. Editable at runtime via Prefs;
    // these are the defaults for Gate + Garage Door 1..3 (5th added later).
    val defaultDoors = linkedMapOf(
        1 to "Garage Door 1",
        2 to "Garage Door 2",
        3 to "Garage Door 3",
        // 4 to "Garage Door 4",  // add when the 5th opener is installed
    )
    const val DEFAULT_GATE = "Gate"

    private val numberWords = mapOf(
        "1" to 1, "one" to 1, "won" to 1,
        "2" to 2, "two" to 2, "too" to 2, "to" to 2,
        "3" to 3, "three" to 3, "tree" to 3,
        "4" to 4, "four" to 4, "for" to 4, "fore" to 4,
        "5" to 5, "five" to 5,
    )
    private val doorCues = listOf("door", "garage", "garge", "garaje")
    private val gateCues = listOf("gate", "gates")

    /**
     * All devices named in one phrase, in the order spoken, de-duplicated.
     * "open garage door 2 and gate" -> [Garage Door 2, Gate]
     * "open the gate" -> [Gate]
     * unrecognized -> [] (caller shows an error / asks again)
     *
     * @param text recognized phrase (wake word may or may not still be present)
     * @param gateTile the myQ tile name for the gate
     * @param doors map of number -> myQ tile name for installed garage doors
     */
    fun parseAll(
        text: String?,
        gateTile: String = DEFAULT_GATE,
        doors: Map<Int, String> = defaultDoors,
    ): List<String> {
        if (text.isNullOrBlank()) return emptyList()
        val p = text.lowercase()
            .replace(Regex("[^a-z0-9 ]+"), " ")
            .replace(Regex("\\s+"), " ")
            .trim()
        if (p.isEmpty()) return emptyList()
        val tokens = p.split(" ")

        val found = mutableListOf<Pair<Int, String>>()  // (token index, tile)

        // Gate: match the whole token so "garage" can never register as "gate".
        tokens.forEachIndexed { i, tok ->
            if (gateCues.contains(tok)) found.add(i to gateTile)
        }

        // Garage door N: need a door/garage cue somewhere, then every known number.
        if (doorCues.any { p.contains(it) }) {
            tokens.forEachIndexed { i, tok ->
                val n = numberWords[tok]
                if (n != null && doors.containsKey(n)) found.add(i to doors[n]!!)
            }
        }

        return found.sortedBy { it.first }.map { it.second }.distinct()
    }

    /** Single-device convenience: first named device, or null. */
    fun parse(
        text: String?,
        gateTile: String = DEFAULT_GATE,
        doors: Map<Int, String> = defaultDoors,
    ): String? = parseAll(text, gateTile, doors).firstOrNull()
}

# Keep Vosk/JNA native bridges.
-keep class org.vosk.** { *; }
-keep class com.sun.jna.** { *; }
-dontwarn com.sun.jna.**
-dontwarn java.awt.**

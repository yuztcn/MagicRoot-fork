# Keep the complete public Stellar/Shizuku bridge surface. These jars are
# prebuilt and contain AIDL/Parcelable/provider code plus R8-generated lambdas
# referenced across the app/manager boundary.
-keep class roro.stellar.** { *; }
-keep class com.stellar.** { *; }
-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }

# Manifest components / framework entry points.
# Keep class/member names and line numbers for readable diagnostic logs,
# while allowing R8 to strip unreachable methods and fields.
-keep class com.aoki.magicroot.MainActivity {
    public <init>();
}
-keepnames class com.aoki.magicroot.**
-keepclassmembernames class com.aoki.magicroot.** { *; }

-keepattributes Signature,InnerClasses,EnclosingMethod,Annotation,SourceFile,LineNumberTable
-dontwarn org.jetbrains.annotations.**

# Compose/Miuix do not rely on removed Android APIs on this minSdk.
-dontwarn androidx.compose.**

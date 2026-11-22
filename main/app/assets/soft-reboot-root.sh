#!/system/bin/sh
# Root wrapper for the verified module-lifecycle + zygote restart path.
# ksud selection and all stages live in lsposed-hotfix.sh itself.
exec sh /data/local/tmp/magic/lsposed-hotfix.sh

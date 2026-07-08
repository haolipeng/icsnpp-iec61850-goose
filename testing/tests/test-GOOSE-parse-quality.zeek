# @TEST-DOC: Test normal GOOSE replay emits successful structured parse quality fields.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: awk 'BEGIN { FS = "\t"; status = 0; error = 0 } /^#fields/ { for (i = 1; i <= NF; i++) { if ($i == "parse_status") status = i - 1; if ($i == "parse_error") error = i - 1 } next } /^#/ { next } { if (status == 0 || error == 0 || $status != "ok" || $error != "none") exit 1 }' goose.log

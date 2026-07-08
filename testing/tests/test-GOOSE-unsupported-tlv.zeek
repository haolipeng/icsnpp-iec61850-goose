# @TEST-DOC: Test recognized GOOSE with an unsupported context tag logs partial parse quality.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_unsupported_tlv.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

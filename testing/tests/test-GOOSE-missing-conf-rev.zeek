# @TEST-DOC: Test GOOSE missing soft-required conf_rev logs partial parse quality.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_conf_rev.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

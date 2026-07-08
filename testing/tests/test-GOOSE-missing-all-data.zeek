# @TEST-DOC: Test recognized GOOSE without AllData logs partial parse quality.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_all_data.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

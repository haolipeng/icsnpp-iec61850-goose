# @TEST-DOC: Test GOOSE missing soft-required dataset logs partial parse quality.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_dataset.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

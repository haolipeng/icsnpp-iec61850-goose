# @TEST-DOC: Test GOOSE missing required gocb_ref logs failed parse quality.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_gocb_ref.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

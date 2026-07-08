# @TEST-DOC: Test truncated GOOSE traffic does not crash and logs stable parse failure.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_truncated.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

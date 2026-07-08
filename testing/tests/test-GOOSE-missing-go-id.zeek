# @TEST-DOC: Test GOOSE missing optional go_id keeps parse quality ok and logs go_id unset.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_go_id.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

# @TEST-DOC: Test GOOSE missing optional timestamp keeps parse quality ok and logs timestamp fields unset.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_timestamp.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

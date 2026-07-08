# @TEST-DOC: Test malformed ASN.1 GOOSE traffic logs stable parse failure.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_malformed_asn1.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

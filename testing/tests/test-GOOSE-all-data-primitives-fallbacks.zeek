# @TEST-DOC: Test GOOSE AllData primitive/fallback values are logged as a stable complete TLV digest.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_all_data_primitives_fallbacks.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

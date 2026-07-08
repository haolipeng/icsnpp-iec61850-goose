# @TEST-DOC: Test GOOSE missing soft-required num_dat_set_entries logs partial parse quality.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE_missing_num_dat_set_entries.pcap ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

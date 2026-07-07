# @TEST-DOC: Test optional AllData raw hex logging for GOOSE forensic output.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/GOOSE.pcap ${PACKAGE} %INPUT -e 'redef goose::log_all_data_raw_hex=T;' >output1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff goose.log

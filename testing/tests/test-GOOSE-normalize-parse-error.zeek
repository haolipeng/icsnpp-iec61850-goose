# @TEST-DOC: Test Spicy parser error normalization maps raw messages to stable parse_error codes.
#
# @TEST-EXEC: zeek ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1

event zeek_init()
{
    print goose::normalize_parse_error("unexpected end of data");
    print goose::normalize_parse_error("not enough data");
    print goose::normalize_parse_error("expected 8 bytes but 3 available");
    print goose::normalize_parse_error("invalid BER length encoding");
}

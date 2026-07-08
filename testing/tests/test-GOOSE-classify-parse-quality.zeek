# @TEST-DOC: Test GOOSE parse quality classifier maps PRD contract branches to stable status/error pairs.
#
# @TEST-EXEC: zeek ${PACKAGE} %INPUT >output1
# @TEST-EXEC: btest-diff output1

event zeek_init()
{
    local ok_input: goose::ParseQualityInput = [
        $has_src_mac=T,
        $has_dst_mac=T,
        $has_appid=T,
        $seen_gocb_ref=T,
        $seen_st_num=T,
        $seen_sq_num=T,
        $seen_dataset=T,
        $seen_conf_rev=T,
        $seen_num_dat_set_entries=T,
        $seen_all_data=T,
        $parser_warning=goose::PARSE_ERROR_NONE
    ];

    local warning_input = copy(ok_input);
    warning_input$parser_warning = goose::PARSE_ERROR_UNSUPPORTED_TLV;
    local warning_quality = goose::classify_parse_quality(warning_input);
    print fmt("%s/%s", warning_quality$status, warning_quality$error);

    local missing_dataset_input = copy(ok_input);
    missing_dataset_input$seen_dataset = F;
    local missing_dataset_quality = goose::classify_parse_quality(missing_dataset_input);
    print fmt("%s/%s", missing_dataset_quality$status, missing_dataset_quality$error);

    local missing_conf_rev_input = copy(ok_input);
    missing_conf_rev_input$seen_conf_rev = F;
    local missing_conf_rev_quality = goose::classify_parse_quality(missing_conf_rev_input);
    print fmt("%s/%s", missing_conf_rev_quality$status, missing_conf_rev_quality$error);

    local missing_entries_input = copy(ok_input);
    missing_entries_input$seen_num_dat_set_entries = F;
    local missing_entries_quality = goose::classify_parse_quality(missing_entries_input);
    print fmt("%s/%s", missing_entries_quality$status, missing_entries_quality$error);
}

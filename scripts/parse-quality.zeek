module goose;

export {
    const PARSE_STATUS_OK = "ok";
    const PARSE_STATUS_PARTIAL = "partial";
    const PARSE_STATUS_FAILED = "failed";

    const PARSE_ERROR_NONE = "none";
    const PARSE_ERROR_MISSING_REQUIRED_FIELD = "missing_required_field";
    const PARSE_ERROR_MISSING_ALL_DATA = "missing_all_data";
    const PARSE_ERROR_TRUNCATED_PACKET = "truncated_packet";
    const PARSE_ERROR_MALFORMED_ASN1 = "malformed_asn1";

    type ParseQuality: record {
        status: string;
        error: string;
    };

    type ParseQualityInput: record {
        has_src_mac: bool;
        has_dst_mac: bool;
        has_appid: bool;
        seen_gocb_ref: bool;
        seen_st_num: bool;
        seen_sq_num: bool;
        seen_dataset: bool;
        seen_conf_rev: bool;
        seen_num_dat_set_entries: bool;
        seen_all_data: bool;
        parser_warning: string;
    };

    global classify_parse_quality: function(input: ParseQualityInput): ParseQuality;
    global normalize_parse_error: function(parser_error: string): string;
}

function classify_parse_quality(input: ParseQualityInput): ParseQuality
{
    # 缺少关键字段src_mac/dst_mac/appid/gocb_ref/st_num/seen_sq_num
    # 直接返回失败 + 缺失核心字段
    if ( ! input$has_src_mac || ! input$has_dst_mac || ! input$has_appid || ! input$seen_gocb_ref || ! input$seen_st_num || ! input$seen_sq_num )
        return [$status=PARSE_STATUS_FAILED, $error=PARSE_ERROR_MISSING_REQUIRED_FIELD];

    # 缺少 AllData，判为 partial
    if ( ! input$seen_all_data )
        return [$status=PARSE_STATUS_PARTIAL, $error=PARSE_ERROR_MISSING_ALL_DATA];

    # parser_warning 表示 Message 已解析完成后的可恢复告警；
    # Spicy %error 解析失败走 goose_packet_error，并归类为 failed。
    if ( input$parser_warning != PARSE_ERROR_NONE )
        return [$status=PARSE_STATUS_PARTIAL, $error=input$parser_warning];

    # 非必需字段缺失，判为 partial
    if ( ! input$seen_dataset || ! input$seen_conf_rev || ! input$seen_num_dat_set_entries )
        return [$status=PARSE_STATUS_PARTIAL, $error=PARSE_ERROR_MISSING_REQUIRED_FIELD];

    # 解析成功，判定为OK
    return [$status=PARSE_STATUS_OK, $error=PARSE_ERROR_NONE];
}

function normalize_parse_error(parser_error: string): string
{
    if ( /truncat|unexpected end|end of data|not enough data|short read|eof|EOD|expected .* bytes .* available/ in parser_error )
        return PARSE_ERROR_TRUNCATED_PACKET;

    return PARSE_ERROR_MALFORMED_ASN1;
}

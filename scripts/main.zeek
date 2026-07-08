module goose;

export {
    # Create an ID for our new stream. By convention, this is called "LOG".
    redef enum Log::ID += { LOG };

    const log_all_data_raw_hex = F &redef;

    # IECGoosePdu ::= SEQUENCE {
	# 	gocbRef 			[0] IMPLICIT 	VISIBLE-STRING,
	#	timeAllowedtoLive 		[1] IMPLICIT 	INTEGER,
	#	datSet 				[2] IMPLICIT 	VISIBLE-STRING,
	#   	goID 				[3] IMPLICIT 	VISIBLE-STRING OPTIONAL,
	#	T 				[4] IMPLICIT 	UtcTime,
	#	stNum 				[5] IMPLICIT 	INTEGER,
	#	sqNum 				[6] IMPLICIT 	INTEGER,
	#	simulation 			[7] IMPLICIT 	BOOLEAN DEFAULT FALSE,
	#	confRev 			[8] IMPLICIT 	INTEGER,
	#	ndsCom 				[9] IMPLICIT 	BOOLEAN DEFAULT FALSE,
	#	numDatSetEntries 		[10] IMPLICIT 	INTEGER,
	#	allData 			[11] IMPLICIT 	SEQUENCE OF Data,
	#	}

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time                        &log;
        src_mac: string                 &log &optional;
        dst_mac: string                 &log &optional;
        eth_type: string                &log;
        appid: string                   &log;
        length: int                     &log;
        gocb_ref: string                &log;
        time_allowed_to_live: int       &log;
        dataset: string                 &log;
        go_id: string                   &log &optional;
        timestamp: time                 &log &optional;
        timestamp_quality: string       &log &optional;
        st_num: int                     &log;
        sq_num: int                     &log;
        simulation: bool                &log;
        conf_rev: int                   &log;
        nds_com: bool                   &log;
        num_dat_set_entries: int        &log;
        all_data_hash: string           &log;
        all_data_raw_hex: string        &log;
        parse_status: string            &log;
        parse_error: string             &log;
    };
}

event zeek_init() &priority=20
{
    print "Initializing IEC 61850 GOOSE analyzer";

    # Create the stream. This adds a default filter automatically.
    Log::create_stream(goose::LOG, [$columns=Info, $path="goose"]);

    if ( ! PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x88b8, PacketAnalyzer::ANALYZER_SPICY_GOOSE) ) {
        print "Cannot register GOOSE analyzer";
    } else {
        print "Registered IEC 61850 goose analyzer for VLAN";
    }

    if ( ! PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88b8, PacketAnalyzer::ANALYZER_SPICY_GOOSE) ) {
        print "Cannot register GOOSE analyzer";
    } else {
        print "Registered IEC 61850 goose analyzer for ETHERNET";
    }
}

# event defined in goose.evt.
event goose::goose_packet(pkt: raw_pkt_hdr, appid: int, length: int, gocbRef: string, timeAllowedtoLive:int, dataSet: string, goID: string, secondSinceEpoch: count, fractionOfSecond: count, timeQuality: count, stNum: int, sqNum: int, simulation: bool, confRev: int, ndsCom: bool, numDatSetEntries: int, allDataRawHex: string, seenGocbRef: bool, seenDataSet: bool, seenTimestamp: bool, seenStNum: bool, seenSqNum: bool, seenConfRev: bool, seenNumDatSetEntries: bool, seenAllData: bool, parserWarning: string)
{
#    print "Detected a goose packet.";

    # AllData 原始 TLV hex 默认不直接写入日志，避免默认日志过大。
    # 但 allDataRawHex 用于后续 hash 计算。
    local raw_hex = "";
    if ( log_all_data_raw_hex )
        raw_hex = allDataRawHex;

    # 对 AllData 完整 TLV（tag + length + value）计算稳定摘要。
    # 缺少 AllData 时保持为空字符串。
    local all_data_hash = "";
    if ( allDataRawHex != "" )
        all_data_hash = sha256_hash(hexstr_to_bytestring(allDataRawHex));

    # 判断L2的src mac和dst mac值是否存在
    local has_src_mac = pkt?$l2 && pkt$l2?$src;
    local has_dst_mac = pkt?$l2 && pkt$l2?$dst;

    # 根据Spicy层 seen* 标志来分类解析质量
    # classify_parse_quality() 内部负责区分 ok / partial / failed。
    local parse_quality = classify_parse_quality([
        $has_src_mac=has_src_mac,
        $has_dst_mac=has_dst_mac,
        $has_appid=T,
        $seen_gocb_ref=seenGocbRef,
        $seen_st_num=seenStNum,
        $seen_sq_num=seenSqNum,
        $seen_dataset=seenDataSet,
        $seen_conf_rev=seenConfRev,
        $seen_num_dat_set_entries=seenNumDatSetEntries,
        $seen_all_data=seenAllData,
        $parser_warning=parserWarning
    ]);

    # 先组装必填日志字段和派生字段。
    # 这里同时完成字段命名规范化，例如 gocbRef -> gocb_ref、stNum -> st_num。
    local rec: goose::Info = [
        $ts=network_time(),
        $eth_type="0x88b8",
        $appid=fmt("0x%x", appid),
        $length=length,
        $gocb_ref=gocbRef,
        $time_allowed_to_live=timeAllowedtoLive,
        $dataset=dataSet,
        $st_num=stNum,
        $sq_num=sqNum,
        $simulation=simulation,
        $conf_rev=confRev,
        $nds_com=ndsCom,
        $num_dat_set_entries=numDatSetEntries,
        $all_data_hash=all_data_hash,
        $all_data_raw_hex=raw_hex,
        $parse_status=parse_quality$status,
        $parse_error=parse_quality$error
    ];

    # 可选字段未出现时保持 unset，日志输出为 "-"。
    if ( goID != "" ) rec$go_id = goID;

    # 如果Timestamp字段存在，则对timestamp和timestamp_quality字段赋值
    if ( seenTimestamp ) {
        rec$timestamp = double_to_time(count_to_double(secondSinceEpoch) + count_to_double(fractionOfSecond) / 16777216.0);
        rec$timestamp_quality = fmt("0x%x", timeQuality);
    }

    # L2 信息存在时，对src_mac和dst_mac进行赋值。
    if ( pkt?$l2 ) {
        if ( pkt$l2?$src ) rec$src_mac = pkt$l2$src;
        if ( pkt$l2?$dst ) rec$dst_mac = pkt$l2$dst;
    }

    # 写入 goose.log。
    Log::write(goose::LOG, rec);
}

event goose::goose_packet_error(pkt: raw_pkt_hdr, appid: int, length: int, parseError: string)
{
    local normalized_error = normalize_parse_error(parseError);

    local rec: goose::Info = [
        $ts=network_time(),
        $eth_type="0x88b8",
        $appid=fmt("0x%x", appid),
        $length=length,
        $gocb_ref="",
        $time_allowed_to_live=0,
        $dataset="",
        $st_num=0,
        $sq_num=0,
        $simulation=F,
        $conf_rev=0,
        $nds_com=F,
        $num_dat_set_entries=0,
        $all_data_hash="",
        $all_data_raw_hex="",
        $parse_status=PARSE_STATUS_FAILED,
        $parse_error=normalized_error
    ];

    if ( pkt?$l2 ) {
        if ( pkt$l2?$src ) rec$src_mac = pkt$l2$src;
        if ( pkt$l2?$dst ) rec$dst_mac = pkt$l2$dst;
    }

    Log::write(goose::LOG, rec);
}

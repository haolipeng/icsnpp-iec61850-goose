module goose;

export {
    # Create an ID for our new stream. By convention, this is called "LOG".
    redef enum Log::ID += { LOG };

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
        timestamp: time                 &log;
        st_num: int                     &log;
        sq_num: int                     &log;
        simulation: bool                &log;
        conf_rev: int                   &log;
        nds_com: bool                   &log;
        num_dat_set_entries: int        &log;
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
event goose::goose_packet(pkt: raw_pkt_hdr, appid: int, length: int, gocbRef: string, timeAllowedtoLive:int, dataSet: string, goID: string, t: time, stNum: int, sqNum: int, simulation: bool, confRev: int, ndsCom: bool, numDatSetEntries: int)
{
#    print "Detected a goose packet.";

    local rec: goose::Info = [$ts=network_time(), $eth_type="0x88b8", $appid=fmt("0x%x", appid), $length=length, $gocb_ref=gocbRef, $time_allowed_to_live=timeAllowedtoLive, $dataset=dataSet, $timestamp=t, $st_num=stNum, $sq_num=sqNum, $simulation=simulation, $conf_rev=confRev, $nds_com=ndsCom, $num_dat_set_entries=numDatSetEntries];

    if ( goID != "" ) rec$go_id = goID;

    if ( pkt?$l2 ) {
        if ( pkt$l2?$src ) rec$src_mac = pkt$l2$src;
        if ( pkt$l2?$dst ) rec$dst_mac = pkt$l2$dst;
    }

    Log::write(goose::LOG, rec);
}

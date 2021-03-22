package com.fortify.ssc.parser.php.security_checker.parser;

import java.io.IOException;
import java.util.Date;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.util.ssc.parser.json.ScanDataStreamingJsonParser;

public class ScanParser {
	private final ScanData scanData;
    private final ScanBuilder scanBuilder;
    
	public ScanParser(final ScanData scanData, final ScanBuilder scanBuilder) {
		this.scanData = scanData;
		this.scanBuilder = scanBuilder;
	}
	
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/*", jp -> scanBuilder.setNumFiles(jp.countObjectEntries()))
			.parse(scanData);
		scanBuilder.setScanDate(new Date()); // Required but not available in input
		scanBuilder.completeScan();
	}
}

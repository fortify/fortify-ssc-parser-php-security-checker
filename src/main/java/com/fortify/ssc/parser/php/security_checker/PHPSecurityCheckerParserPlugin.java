package com.fortify.ssc.parser.php.security_checker;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import com.fortify.ssc.parser.php.security_checker.parser.ScanParser;
import com.fortify.ssc.parser.php.security_checker.parser.VulnerabilitiesParser;

public class PHPSecurityCheckerParserPlugin implements ParserPlugin<CustomVulnAttribute> {
    private static final Logger LOG = LoggerFactory.getLogger(PHPSecurityCheckerParserPlugin.class);

    @Override
    public void start() throws Exception {
        LOG.info("{} is starting", this.getClass().getSimpleName());
    }

    @Override
    public void stop() throws Exception {
        LOG.info("{} is starting", this.getClass().getSimpleName());
    }

    @Override
    public Class<CustomVulnAttribute> getVulnerabilityAttributesClass() {
        return CustomVulnAttribute.class;
    }

    @Override
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder) throws ScanParsingException, IOException {
        new ScanParser(scanData, scanBuilder).parse();
    }

	@Override
	public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler) throws ScanParsingException, IOException {
		new VulnerabilitiesParser(scanData, vulnerabilityHandler).parse();
	}
}

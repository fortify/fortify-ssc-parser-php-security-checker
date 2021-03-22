package com.fortify.ssc.parser.php.security_checker.parser;

import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.core.JsonToken;
import com.fortify.plugin.api.BasicVulnerabilityBuilder.Priority;
import com.fortify.ssc.parser.php.security_checker.CustomVulnAttribute;
import com.fortify.ssc.parser.php.security_checker.domain.DependencyAdvisory;
import com.fortify.ssc.parser.php.security_checker.domain.DependencyVersionAndAdvisories;
import com.fortify.plugin.api.FortifyAnalyser;
import com.fortify.plugin.api.FortifyKingdom;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.util.ssc.parser.EngineTypeHelper;
import com.fortify.util.ssc.parser.HandleDuplicateIdVulnerabilityHandler;
import com.fortify.util.ssc.parser.json.ScanDataStreamingJsonParser;

public class VulnerabilitiesParser {
	private static final String ENGINE_TYPE = EngineTypeHelper.getEngineType();
	private final ScanData scanData;
	private final VulnerabilityHandler vulnerabilityHandler;

    public VulnerabilitiesParser(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler) {
    	this.scanData = scanData;
		this.vulnerabilityHandler = new HandleDuplicateIdVulnerabilityHandler(vulnerabilityHandler);
	}
    
    /**
	 * Main method to commence parsing the input provided by the configured {@link ScanData}.
	 * @throws ScanParsingException
	 * @throws IOException
	 */
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.expectedStartTokens(JsonToken.START_OBJECT)
			.handler("/*", DependencyVersionAndAdvisories.class, this::buildVulnerabilitiesForDependency)
			.parse(scanData);
	}
	
	
	private final void buildVulnerabilitiesForDependency(String dependencyName, DependencyVersionAndAdvisories dependencyVersionAndAdvisories) {
		DependencyAdvisory[] advisories = dependencyVersionAndAdvisories.getAdvisories();
		String dependencyVersion = dependencyVersionAndAdvisories.getVersion();
		if ( advisories!=null && advisories.length>0 ) {
			for ( DependencyAdvisory advisory : advisories ) {
				buildVulnerabilityForDependency(dependencyName, dependencyVersion, advisory);
			}
		}
	}
	
	private final void buildVulnerabilityForDependency(String dependencyName, String dependencyVersion,	DependencyAdvisory dependencyAdvisory) {
		StaticVulnerabilityBuilder vb = vulnerabilityHandler.startStaticVulnerability(getInstanceId(dependencyName, dependencyVersion, dependencyAdvisory));
		
		// Set meta-data
		vb.setEngineType(ENGINE_TYPE);
		vb.setKingdom(FortifyKingdom.ENVIRONMENT.getKingdomName());
		vb.setAnalyzer(FortifyAnalyser.CONFIGURATION.getAnalyserName());
		
		// Set mandatory values to JavaDoc-recommended values
		vb.setAccuracy(5.0f);
		vb.setConfidence(2.5f);
		vb.setLikelihood(2.5f);
		
		// Set standard vulnerability fields based on input
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory("Unpatched Application");
		vb.setFileName(dependencyName);
		vb.setPriority(Priority.Critical);
		
		vb.setVulnerabilityAbstract(dependencyAdvisory.getTitle());
		
		// Set custom attributes based on input
		vb.setStringCustomAttributeValue(CustomVulnAttribute.DependencyVersion, dependencyVersion);
		vb.setStringCustomAttributeValue(CustomVulnAttribute.AdvisoryLink, dependencyAdvisory.getLink());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.AdvisoryCve, dependencyAdvisory.getCve());
		
		vb.completeVulnerability();
	}
	
	/**
	 * Calculate the issue instance id, using a combination of feature name, feature version, and vulnerability name
	 */
	private final String getInstanceId(String dependencyName, String dependencyVersion, DependencyAdvisory dependencyAdvisory) {
		String cveOrTitleOrLink = getFirstNonBlank(
				dependencyAdvisory.getCve(),
				dependencyAdvisory.getTitle(),
				dependencyAdvisory.getLink());
		return DigestUtils.sha256Hex(String.join("|", dependencyName, dependencyVersion, cveOrTitleOrLink));
	}
	
	private final String getFirstNonBlank(String... strings) {
		return Arrays.stream(strings).filter(StringUtils::isNotBlank).findFirst().orElse("Unknown");
	}
}

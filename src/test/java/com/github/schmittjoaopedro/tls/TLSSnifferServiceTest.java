package com.github.schmittjoaopedro.tls;

import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TLSSnifferServiceTest {

    private static final String TEST_URL = "https://api.stackexchange.com/2.3/articles?order=desc&sort=activity&site=stackoverflow";

    @Before
    public void setUp() {
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", "certs/truststore.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "truststore");
    }

    @Test
    public void protocolTLS12_shouldLogSession() {
        TLSSnifferService snifferService = new TLSSnifferService();
        String analysisLog = snifferService.runAnalysis(TEST_URL, "TLSv1.2", null, false);
        System.out.println(analysisLog);

        assertThat(analysisLog).contains("Calling endpoint using Detailed client");
        assertThat(analysisLog).contains("Response status: 200");

        assertThat(analysisLog).contains("TLS session information");
        assertThat(analysisLog).contains("Protocol: TLSv1.2");
        assertThat(analysisLog).contains("X509 Certificate");
    }

    @Test
    public void protocolTLS12AndLog_shouldLogHandshake() {
        TLSSnifferService snifferService = new TLSSnifferService();
        String analysisLog = snifferService.runAnalysis(TEST_URL, "TLSv1.2", null, true);
        System.out.println(analysisLog);

        assertThat(analysisLog).contains("Calling endpoint using Detailed client");
        assertThat(analysisLog).contains("Response status: 200");

        assertThat(analysisLog).contains("TLS session information");
        assertThat(analysisLog).contains("Protocol: TLSv1.2");
        assertThat(analysisLog).contains("X509 Certificate");

        assertThat(analysisLog).contains("TLS transmission raw packets");
        assertThat(analysisLog).contains("Output packet: \n160303"); // Handshake packet (should have 2)
        assertThat(analysisLog).contains("Input packet: \n160303"); // Handshake packet
        assertThat(analysisLog).contains("Input packet: \n140303"); // ChangeCipherSpec
        assertThat(analysisLog).contains("Output packet: \n170303"); // Application packet
        assertThat(analysisLog).contains("Input packet: \n170303"); // Application packet
    }

}

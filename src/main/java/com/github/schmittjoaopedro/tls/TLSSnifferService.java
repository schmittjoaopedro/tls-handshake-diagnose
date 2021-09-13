package com.github.schmittjoaopedro.tls;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.security.cert.X509Certificate;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import java.util.Iterator;

import static com.github.schmittjoaopedro.tls.ConversionUtils.byteArrayToHex;

/**
 * How to Import Public Certificates into Java’s Truststore from a Browser
 * https://medium.com/expedia-group-tech/how-to-import-public-certificates-into-javas-truststore-from-a-browser-a35e49a806dc
 * <p>
 * How to find what SSL/TLS version is used in Java
 * https://stackoverflow.com/questions/10500511/how-to-find-what-ssl-tls-version-is-used-in-java
 * <p>
 * Debugging SSL/TLS Connections (Oracle)
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/ReadDebug.html
 * <p>
 * TLS detailed
 * https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art059
 * <p>
 * SSL Report: www.stackoverflow.com
 * https://www.ssllabs.com/ssltest/analyze.html?d=www.stackoverflow.com
 * <p>
 * SSL Handshake diagram
 * https://upload.wikimedia.org/wikipedia/commons/d/d3/Full_TLS_1.2_Handshake.svg
 * <p>
 * Transport Layer Security
 * https://en.wikipedia.org/wiki/Transport_Layer_Security
 * <p>
 * The Illustrated TLS Connection
 * https://tls.ulfheim.net/
 * <p>
 * Mapping OpenSSL cipher suite names to IANA names
 * https://testssl.sh/openssl-iana.mapping.html
 * <p>
 * Hex To String Converter
 * http://string-functions.com/hex-string.aspx
 */
public class TLSSnifferService {

    public String runAnalysis(String url, String protocol, String cipher, boolean logHandshake) {
        StringBuilder analysisLog = new StringBuilder("\n");
        printServiceProviders(analysisLog);
        printDetailedDiagnostic(analysisLog, url, protocol, cipher, logHandshake);
        return analysisLog.toString();
    }

    private void printDetailedDiagnostic(StringBuilder analysisLog, String url, String protocol, String cipher, boolean logHandshake) {
        SSLContext sslContext = null;
        HttpResponse response = null;
        PacketsSniffer packetsSniffer = new PacketsSniffer();
        try {
            // Factory
            KeyStore keyStore = KeyStore.getInstance(System.getProperty("javax.net.ssl.trustStoreType"));
            keyStore.load(getClass().getClassLoader().getResourceAsStream(System.getProperty("javax.net.ssl.trustStore")),
                    System.getProperty("javax.net.ssl.trustStorePassword").toCharArray());
            sslContext = SSLContexts.custom()
                    .loadTrustMaterial(keyStore)
                    .useProtocol(StringUtils.isBlank(protocol) ? null : protocol)
                    .build();
            PacketsSnifferConnectionManager customConnectionManager = new PacketsSnifferConnectionManager(
                    packetsSniffer,
                    sslContext,
                    // if protocol and ciphers are not defined, those provided as default by webserver are used (null)
                    StringUtils.isBlank(protocol) ? new String[]{System.getProperty("https.protocols")} : new String[]{protocol},
                    StringUtils.isBlank(cipher) ? null : new String[]{cipher});
            CloseableHttpClient httpClient = HttpClients
                    .custom()
                    .setConnectionManager(customConnectionManager)
                    .build();
            // Client
            HttpGet httpGet = new HttpGet(url);
            response = httpClient.execute(httpGet);
        } catch (Exception ex) {
            analysisLog.append("Error requesting URL\n");
            analysisLog.append(ex.getMessage());
            analysisLog.append("\n");
        }
        // Logs
        if (sslContext != null) {
            printTLSGeneralInfo(analysisLog, sslContext.getSupportedSSLParameters().getProtocols(), sslContext.getSupportedSSLParameters().getCipherSuites());
        }
        if (response != null) {
            printRequestInfo(analysisLog, "Detailed", url, response);
        }
        if (sslContext != null) {
            Enumeration<byte[]> sessionIds = sslContext.getClientSessionContext().getIds();
            while (sessionIds.hasMoreElements()) {
                printTLSSessionInfo(analysisLog, sslContext.getClientSessionContext().getSession(sessionIds.nextElement()));
            }
        }
        if (logHandshake && packetsSniffer != null) {
            printTLSTransmissionRawPackets(analysisLog, packetsSniffer);
        }
    }

    private void printServiceProviders(StringBuilder analysisLog) {
        analysisLog.append("---------------------------\n");
        analysisLog.append("WebServer service providers\n");
        for (Provider provider : Security.getProviders()) {
            analysisLog.append(provider + "\n");
            for (Provider.Service service : provider.getServices()) {
                if ("SSLContext".equals(service.getType())) {
                    analysisLog.append("\t" + service.getType() + "." + service.getAlgorithm() + "\n");
                }
            }
        }
        analysisLog.append("\n");
    }

    private void printTLSGeneralInfo(StringBuilder analysisLog, String[] protocols, String[] ciphers) {
        analysisLog.append("---------------------------\n");
        analysisLog.append("Request TLS global information\n");
        // General TLS
        analysisLog.append("Supported protocols:\n");
        for (String protocol : protocols) {
            analysisLog.append("\t" + protocol + "\n");
        }
        analysisLog.append("Supported ciphers:\n");
        for (String cipher : ciphers) {
            analysisLog.append("\t" + cipher + "\n");
        }
        analysisLog.append("\n");
    }

    private void printRequestInfo(StringBuilder analysisLog, String client, String url, HttpResponse response) {
        analysisLog.append("---------------------------\n");
        analysisLog.append("Calling endpoint using " + client + " client\n");
        analysisLog.append("Requesting     : " + url + "\n");
        analysisLog.append("Response status: " + response.getStatusLine().getStatusCode() + "\n");
        try {
            analysisLog.append("Response body  : " + EntityUtils.toString(response.getEntity()) + "\n");
        } catch (IOException ex) {
            analysisLog.append("Failed read response body: " + ex.getMessage());
        }
        analysisLog.append("\n");
    }

    private void printTLSSessionInfo(StringBuilder analysisLog, SSLSession sslSession) {
        try {
            analysisLog.append("---------------------------\n");
            analysisLog.append("TLS session information\n");
            analysisLog.append("Client: " + sslSession.getPeerHost() + ":" + sslSession.getPeerPort() + "\n");
            analysisLog.append("\tProtocol: " + sslSession.getProtocol() + "\n");
            analysisLog.append("\tSessionID: " + byteArrayToHex(sslSession.getId()) + "\n");
            analysisLog.append("\tCipherSuite: " + sslSession.getCipherSuite() + "\n");
            for (X509Certificate certificate : sslSession.getPeerCertificateChain()) {
                analysisLog.append("\tX509 Certificate: " + certificate.getSubjectDN() + "\n");
                analysisLog.append("\t\tIssuer: " + certificate.getIssuerDN().getName() + "\n");
                analysisLog.append("\t\tAlgorithm: " + certificate.getSigAlgName() + "\n");
                analysisLog.append("\t\tValidity: " + certificate.getNotAfter() + "\n");
            }
            analysisLog.append("\n");
        } catch (Exception ex) {
            analysisLog.append("Error printing sessions TLS info\n");
            analysisLog.append(ex.getMessage());
            analysisLog.append("\n");
        }
    }

    private void printTLSTransmissionRawPackets(StringBuilder analysisLog, PacketsSniffer packetsSniffer) {
        analysisLog.append("---------------------------\n");
        analysisLog.append("TLS transmission raw packets (https://tls.ulfheim.net/)\n\n");
        Iterator<ByteArrayOutputStream> packetsIterator = packetsSniffer.getAllPackages().iterator();
        while (packetsIterator.hasNext()) {
            ByteArrayOutputStream packet = packetsIterator.next();
            byte[] packetData = packet.toByteArray();
            if (packet != null && packetData.length > 0) {
                if (packetsSniffer.isOutputPacket(packet)) {
                    analysisLog.append("Output packet: \n");
                } else {
                    analysisLog.append("Input packet: \n");
                }
                analysisLog.append(byteArrayToHex(packetData));
                analysisLog.append("\n\n");
            }
        }
        analysisLog.append("\n");
    }
}

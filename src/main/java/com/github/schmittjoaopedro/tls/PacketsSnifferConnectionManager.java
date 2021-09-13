package com.github.schmittjoaopedro.tls;

import org.apache.http.HttpHost;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class PacketsSnifferConnectionManager extends PoolingHttpClientConnectionManager {

    public PacketsSnifferConnectionManager(final PacketsSniffer packetsSniffer,
                                           final SSLContext sslContext,
                                           final String[] supportedProtocols,
                                           final String[] supportedCipherSuites) {
        super(RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", createHttpSocketFactory(packetsSniffer))
                .register("https", createHttpsSocketFactory(packetsSniffer, sslContext, supportedProtocols, supportedCipherSuites))
                .build());
    }

    private static ConnectionSocketFactory createHttpSocketFactory(final PacketsSniffer packetsSniffer) {
        return new ConnectionSocketFactory() {

            @Override
            public Socket createSocket(HttpContext context) {
                return packetsSniffer.createSnifferSocket();
            }

            @Override
            public Socket connectSocket(final int connectTimeout,
                                        final Socket socket,
                                        final HttpHost host,
                                        final InetSocketAddress remoteAddress,
                                        final InetSocketAddress localAddress,
                                        final HttpContext context) throws IOException {
                return PlainConnectionSocketFactory
                        .getSocketFactory()
                        .connectSocket(
                                connectTimeout,
                                socket != null ? socket : createSocket(context),
                                host,
                                remoteAddress,
                                localAddress,
                                context);
            }
        };
    }

    private static LayeredConnectionSocketFactory createHttpsSocketFactory(final PacketsSniffer packetsSniffer,
                                                                           final SSLContext sslContext,
                                                                           final String[] supportedProtocols,
                                                                           final String[] supportedCipherSuites) {

        return new SSLConnectionSocketFactory(
                sslContext,
                supportedProtocols,
                supportedCipherSuites,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER) {
            @Override
            public Socket createLayeredSocket(Socket socket, String target, int port, HttpContext context) throws IOException {
                packetsSniffer.setPacketSniffingActive(true);
                Socket sslSocket = super.createLayeredSocket(socket, target, port, context); // calls handshake
                packetsSniffer.setPacketSniffingActive(false);
                return sslSocket;
            }

            @Override
            public Socket createSocket(HttpContext context) {
                return packetsSniffer.createSnifferSocket();
            }
        };
    }
}

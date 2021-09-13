package com.github.schmittjoaopedro.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.LinkedList;

public class PacketsSniffer {

    private boolean packetSniffingActive = false;

    private final LinkedList<ByteArrayOutputStream> inputPacketBytes = new LinkedList<>();
    private final LinkedList<ByteArrayOutputStream> outputPacketBytes = new LinkedList<>();
    private final LinkedList<ByteArrayOutputStream> allPacketBytes = new LinkedList<>();

    public Socket createSnifferSocket() {
        return new Socket() {
            @Override
            public OutputStream getOutputStream() throws IOException {
                final OutputStream base = super.getOutputStream();
                if (isPacketSniffingActive()) {
                    return new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            createFirstOutputPacket();
                            anticipatePacketForInputStream();
                            sniffOutput(b);
                            base.write(b);
                        }

                        @Override
                        public void write(byte[] b, int off, int len) throws IOException {
                            createFirstOutputPacket();
                            anticipatePacketForInputStream();
                            sniffOutput(b, off, len);
                            base.write(b, off, len);
                        }
                    };
                }
                return base;
            }

            @Override
            public InputStream getInputStream() throws IOException {
                final InputStream base = super.getInputStream();
                if (isPacketSniffingActive()) {
                    return new InputStream() {
                        @Override
                        public int read() throws IOException {
                            createFirstInputPacket();
                            anticipatePacketForOutputStream();
                            int b = base.read();
                            sniffInput(b);
                            return b;
                        }

                        @Override
                        public int read(byte[] b, int off, int len) throws IOException {
                            createFirstInputPacket();
                            anticipatePacketForOutputStream();
                            int data = base.read(b, off, len);
                            sniffInput(b, off, len);
                            return data;
                        }
                    };
                }
                return base;
            }
        };
    }

    private void createFirstOutputPacket() {
        if (outputPacketBytes.isEmpty()) {
            outputPacketBytes.addLast(new ByteArrayOutputStream());
            allPacketBytes.addLast(outputPacketBytes.getLast());
        }
    }

    private void anticipatePacketForInputStream() {
        if (!inputPacketBytes.isEmpty() && inputPacketBytes.getLast().size() != 0) {
            inputPacketBytes.addLast(new ByteArrayOutputStream());
            allPacketBytes.addLast(inputPacketBytes.getLast());
        }
    }

    private void sniffOutput(int b) {
        outputPacketBytes.getLast().write(b);
    }

    private void sniffOutput(byte[] b, int off, int len) {
        outputPacketBytes.getLast().write(b, off, len);
    }

    private void createFirstInputPacket() {
        if (inputPacketBytes.isEmpty()) {
            inputPacketBytes.addLast(new ByteArrayOutputStream());
            allPacketBytes.addLast(inputPacketBytes.getLast());
        }
    }

    private void anticipatePacketForOutputStream() {
        if (!outputPacketBytes.isEmpty() && outputPacketBytes.getLast().size() != 0) {
            outputPacketBytes.addLast(new ByteArrayOutputStream());
            allPacketBytes.addLast(outputPacketBytes.getLast());
        }
    }

    private void sniffInput(int b) {
        inputPacketBytes.getLast().write(b);
    }

    private void sniffInput(byte[] b, int off, int len) {
        inputPacketBytes.getLast().write(b, off, len);
    }

    public boolean isPacketSniffingActive() {
        return packetSniffingActive;
    }

    public void setPacketSniffingActive(boolean packetSniffingActive) {
        this.packetSniffingActive = packetSniffingActive;
    }

    public LinkedList<ByteArrayOutputStream> getAllPackages() {
        return allPacketBytes;
    }

    public boolean isOutputPacket(ByteArrayOutputStream packet) {
        return outputPacketBytes.contains(packet);
    }

}

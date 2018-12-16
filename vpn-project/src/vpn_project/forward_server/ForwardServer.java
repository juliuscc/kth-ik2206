package vpn_project.forward_server;

/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 * <p>
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import vpn_project.crypto.CertificateCrypto;
import vpn_project.crypto.HandshakeCrypto;
import vpn_project.crypto.SessionEncrypter;
import vpn_project.crypto.SessionKey;

import java.io.*;
import java.lang.AssertionError;
import java.lang.Integer;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class ForwardServer {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;

    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private static CertificateCrypto serverCertificate;
    private static CertificateCrypto caCertificate;

    /**
     * Do handshake negotiation with client to authenticate, learn
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();

        try {
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            Logger.log("Incoming handshake connection from " + clientHostPort);

            /* This is where the handshake should take place */

            /* ClientHello Message */
            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.recv(clientSocket);

            if (!clientHello.getParameter("MessageType").equals("ClientHello")) {
                throw new Exception("Received unexpected message");
            }

            CertificateCrypto clientCertificate = new CertificateCrypto(clientHello.getParameter("Certificate"));

            clientCertificate.getCertificate().verify(caCertificate.getCertificate().getPublicKey());
            clientCertificate.getCertificate().checkValidity();

            /* ServerHello Message */
            HandshakeMessage serverHello = new HandshakeMessage();

            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", serverCertificate.encodeCertificate());

            serverHello.send(clientSocket);

            /* Forward Message */
            HandshakeMessage forwardMessage = new HandshakeMessage();
            forwardMessage.recv(clientSocket);

            if (!forwardMessage.getParameter("MessageType").equals("Forward")) {
                throw new Exception("Received unexpected message");
            }
            targetHost = forwardMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(forwardMessage.getParameter("TargetPort"));

            /* Session Message */
            SessionEncrypter sessionEncrypter = new SessionEncrypter(256);
            String sessionKeyString = sessionEncrypter.encodeKey();
            String encryptedKey = new String(HandshakeCrypto.encrypt(sessionKeyString.getBytes(), clientCertificate.getCertificate().getPublicKey()));

            String sessionIVString = sessionEncrypter.encodeIV();
            String encryptedIV = new String(HandshakeCrypto.encrypt(sessionIVString.getBytes(), clientCertificate.getCertificate().getPublicKey()));

            String serverHost = InetAddress.getLocalHost().getHostAddress();

            listenSocket = new ServerSocket();
            listenSocket.bind(new InetSocketAddress(serverHost, 0));

            HandshakeMessage sessionMessage = new HandshakeMessage();
            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", encryptedKey);
            sessionMessage.putParameter("SessionIV", encryptedIV);
            sessionMessage.putParameter("ServerHost", serverHost);
            sessionMessage.putParameter("ServerPort", Integer.toString(listenSocket.getLocalPort()));

            sessionMessage.send(clientSocket);

            clientSocket.close();
            
            Logger.log("Finished with handshake.");
        } catch (Exception e) {
            clientSocket.close();
            throw e;
        }
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer() throws Exception {

        serverCertificate = new CertificateCrypto(true, arguments.get("usercert"));
        caCertificate = new CertificateCrypto(true, arguments.get("cacert"));

        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);

        // Accept client connections and process them until stopped
        while (true) {
            ForwardServerClientThread forwardThread;
            try {

                doHandshake();

                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
                forwardThread.start();
            } catch (IOException e) {
                System.out.println("Establishing connection with client was not possible.");
                System.out.println(e.getMessage());
            }
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
            throws Exception {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);

        ForwardServer srv = new ForwardServer();
        try {
            srv.startForwardServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

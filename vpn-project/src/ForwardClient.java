/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 * <p>
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */


import crypto.CertificateCrypto;
import crypto.HandshakeCrypto;
import crypto.SessionDecrypter;
import crypto.SessionEncrypter;

import java.io.*;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class ForwardClient {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    private static CertificateCrypto clientCertificate;
    private static CertificateCrypto caCertificate;
    private static PrivateKey clientPrivateKey;

    private static SessionDecrypter sessionDecrypter;
    private static SessionEncrypter sessionEncrypter;

    private static void doHandshake() throws IOException, CertificateEncodingException, Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " + arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));


        /* This is where the handshake should take place */

        try {
            /* ClientHello Message */
            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.putParameter("MessageType", "ClientHello");
            clientHello.putParameter("Certificate", clientCertificate.encodeCertificate());
            clientHello.send(socket);

            /* ServerHello Message */
            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.recv(socket);

            if (!serverHello.getParameter("MessageType").equals("ServerHello")) {
                throw new Exception("Received unexpected message");
            }
            CertificateCrypto serverCertificate = new CertificateCrypto(serverHello.getParameter("Certificate"));
            serverCertificate.getCertificate().verify(caCertificate.getCertificate().getPublicKey());
            serverCertificate.getCertificate().checkValidity();

            /* Forward Message */
            HandshakeMessage forwardMessage = new HandshakeMessage();
            forwardMessage.putParameter("MessageType", "Forward");
            forwardMessage.putParameter("TargetHost", arguments.get("targethost"));
            forwardMessage.putParameter("TargetPort", arguments.get("targetport"));
            forwardMessage.send(socket);

            /* Session Message */
            HandshakeMessage sessionMessage = new HandshakeMessage();
            sessionMessage.recv(socket);

            if (!sessionMessage.getParameter("MessageType").equals("Session")) {
                throw new Exception("Received unexpected message");
            }

            serverHost = sessionMessage.getParameter("ServerHost");
            serverPort = Integer.parseInt(sessionMessage.getParameter("ServerPort"));

            byte[] encryptedSessionKey = HandshakeCrypto.byte64Decode(sessionMessage.getParameter("SessionKey"));
            byte[] encryptedSessionIV = HandshakeCrypto.byte64Decode(sessionMessage.getParameter("SessionIV"));

            byte[] sessionKeyByteArray = HandshakeCrypto.decrypt(encryptedSessionKey, clientPrivateKey);
            byte[] ivByteArray = HandshakeCrypto.decrypt(encryptedSessionIV, clientPrivateKey);

            sessionDecrypter = new SessionDecrypter(sessionKeyByteArray, ivByteArray);
            sessionEncrypter = new SessionEncrypter(sessionKeyByteArray, ivByteArray);

            socket.close();

            Logger.log("Finished with handshake.");
        } catch (Exception e) {
            socket.close();
            throw e;
        }
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, CertificateException, Exception {

        clientCertificate = new CertificateCrypto(true, arguments.get("usercert"));
        caCertificate = new CertificateCrypto(true, arguments.get("cacert"));
        clientPrivateKey = CertificateCrypto.getPrivateKeyFromFile(arguments.get("key"));

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;

        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null);
            /* Tell the user, so the user knows where to connect */
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);

            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, sessionDecrypter, sessionEncrypter);
            forwardThread.start();

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch (IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

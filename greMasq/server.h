#ifndef SERVER_H
#define SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QUdpSocket>

class RawsockThread : public QThread
{
    Q_OBJECT
public:
    RawsockThread(QObject *parent = 0);
    void run();
};

class Server : public QObject
{
    Q_OBJECT

public:
    Server(QObject *parent = 0);
    ~Server();
    bool init();

private slots:
    void tcpBytesWritten(qint64 bytes);
    void tcpConnected();
    void tcpDisconnected();
    void tcpError(QAbstractSocket::SocketError error);
    void tcpNewConnection();
    void tcpReadyRead();
    void tcpStateChanged(QAbstractSocket::SocketState state);
    void timerTimeout();
    void udpReadyRead();

private:
    enum {
        pptpLen_msgLen               = 2,
        pptpLen_startCtrlConnRequest = 156,
        pptpLen_startCtrlConnReply   = 156,
        pptpLen_outCallRequest       = 168,
        pptpLen_outCallReply         = 32,
        pptpLen_inCallRequest        = 220,
        pptpLen_inCallReply          = 24,
        pptpLen_inCallConnected      = 28,
        pptpLen_callClearRequest     = 16,
        pptpLen_callDisconnectNotify = 148,
        pptpLen_wanErrorNotify       = 40,
        pptpLen_setLinkInfo          = 24
    };
    enum {
        pptpPos_pptpMsgType                 = 2,
        pptpPos_ctrlMsgType                 = 8,
        pptpPos_outCallRequest_callId       = 12,
        pptpPos_outCallRequest_CallSn       = 14,
        pptpPos_outCallReply_callId         = 12,
        pptpPos_outCallReply_peerCallId     = 14,
        pptpPos_inCallRequest_callId        = 12,
        pptpPos_inCallRequest_CallSn        = 14,
        pptpPos_inCallReply_callId          = 12,
        pptpPos_inCallReply_peerCallId      = 14,
        pptpPos_inCallConnected_peerCallId  = 12,
        pptpPos_callClearRequest_callId     = 12,
        pptpPos_callDisconnectNotify_callId = 12,
        pptpPos_wanErrorNotify_peerCallId   = 12,
        pptpPos_setLinkInfo_peerCallId      = 12
    };
    enum {
        pptpType_startCtrlConnRequest = 1,
        pptpType_startCtrlConnReply   = 2,
        pptpType_stopCtrlConnRequest  = 3,
        pptpType_stopCtrlConnReply    = 4,
        pptpType_echoRequest          = 5,
        pptpType_echoReply            = 6,
        pptpType_outCallRequest       = 7,
        pptpType_outCallReply         = 8,
        pptpType_inCallRequest        = 9,
        pptpType_inCallReply          = 10,
        pptpType_inCallConnected      = 11,
        pptpType_callClearRequest     = 12,
        pptpType_callDisconnectNotify = 13,
        pptpType_wanErrorNotify       = 14,
        pptpType_setLinkInfo          = 15
    };
    struct Link {
        quint16 callIdRx;
        quint16 callIdTx;
        QByteArray dataRx;//接收的报文
        QByteArray dataTx;//发送的报文
        Link *peer;
        QTcpSocket *tcp;
    };
    typedef QHash<QTcpSocket*, Link*> LinkHash;
    typedef QHash<QString, Link*> LinkHashGre;
    void pptpRecv(Link *link);
    void pptpRecv_callClearRequest(Link *link);
    void pptpRecv_callDisconnectNotify(Link *link);
    void pptpRecv_echoReply(Link *link);
    void pptpRecv_echoRequest(Link *link);
    void pptpRecv_inCallConnected(Link *link);
    void pptpRecv_inCallReply(Link *link);
    void pptpRecv_inCallRequest(Link *link);
    void pptpRecv_outCallReply(Link *link);
    void pptpRecv_outCallRequest(Link *link);
    void pptpRecv_setLinkInfo(Link *link);
    void pptpRecv_startCtrlConnReply(Link *link);
    void pptpRecv_startCtrlConnRequest(Link *link);
    void pptpRecv_stopCtrlConnReply(Link *link);
    void pptpRecv_stopCtrlConnRequest(Link *link);
    void pptpRecv_wanErrorNotify(Link *link);
    QString tcpAddr(QTcpSocket *tcp);
    void tcpInit(QTcpSocket *tcp);
    void tcpSend(Link *link);
    quint32 mCallId;
    LinkHash mLinkHash;
    LinkHashGre mLinkHashGre;
    RawsockThread *mRawsockThread;
    QTcpServer *mTcpServer;
    QUdpSocket *mUdpSocket;

};

#endif // SERVER_H


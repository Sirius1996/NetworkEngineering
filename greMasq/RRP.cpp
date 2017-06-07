#include "server.h"
#include <QDebug>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static sockaddr_in gUdpAddr;
static quint16 gWorkUdpPort = 0;

quint16 rawDecodeUint16(const char *data, int pos)
{
    quint16 result = (quint8)data[pos] * 256 + (quint8)data[pos + 1];
    return result;
}

quint32 rawDecodeUint32(const char *data, int pos)
{
    quint32 result = (quint8)data[pos]*256*256*256 + (quint8)data[pos+1]*256*256 + (quint8)data[pos+2]*256 + (quint8)data[pos+3];
    return result;
}

void rawEncodeUint16(char *data, int pos, quint16 value)
{
    data[pos + 0] = (value >> 8) & 0x00ff;
    data[pos + 1] = (value >> 0) & 0x00ff;
}

void rawEncodeUint32(char *data, int pos, quint32 value)
{
    data[pos + 0] = (value >>24) & 0x00ff;
    data[pos + 1] = (value >>16) & 0x00ff;
    data[pos + 2] = (value >> 8) & 0x00ff;
    data[pos + 3] = (value >> 0) & 0x00ff;
}

QString sockAddr(sockaddr_in *addr, bool hasPort)
{
    QString port = hasPort ? (":" + QString::number(ntohs(addr->sin_port))):"";
    return QHostAddress((sockaddr*)addr).toString() + port;
}

#define LINK_CRT(l) qCritical().noquote() << tcpAddr(l->tcp)
#define LINK_DBG(l)    qDebug().noquote() << tcpAddr(l->tcp)
#define LINK_INF(l)     qInfo().noquote() << tcpAddr(l->tcp)
#define LINK_WRN(l)  qWarning().noquote() << tcpAddr(l->tcp)

RawsockThread::RawsockThread(QObject *parent) : QThread(parent)
{
}

void RawsockThread::run()
{
    char buf[65536];
    size_t bufLen = sizeof(buf);

    sockaddr_in greAddr;
    socklen_t addrLen;
    int greFd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (0 > greFd) {
        qCritical().noquote() << "socketGre" << greFd;
        return;
    }
    qInfo() << "greFd" << greFd;
    int maxFd = greFd;
    int udpFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 > udpFd) {
        qCritical().noquote() << "socketUdp" << udpFd;
        return;
    }
    sockaddr_in udpAddr;
    memset(&udpAddr, 0, sizeof(udpAddr));
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    udpAddr.sin_port = 0;
    if (0 > bind(udpFd, (sockaddr*)&udpAddr, sizeof(udpAddr))) {
        qCritical().noquote() << "bindUdp" << sockAddr(&udpAddr, true) << "err" << strerror(errno);
        return;
    }
    addrLen = sizeof(udpAddr);
    if (0 > getsockname(udpFd, (sockaddr*)&udpAddr, &addrLen)) {
        qCritical().noquote() << "getsocknameUdp" << strerror(errno);
        return;
    }
    gWorkUdpPort = ntohs(udpAddr.sin_port);
    qInfo().noquote() << "udpFd" << udpFd << "local" << sockAddr(&udpAddr, true);
    if (maxFd < udpFd) {
        maxFd = udpFd;
    }
    qInfo() << "maxFd" << maxFd;
    fd_set fdSet;
    while (true) {
        FD_ZERO(&fdSet);
        FD_SET(greFd, &fdSet);
        FD_SET(udpFd, &fdSet);
        if (0 > select(maxFd + 1, &fdSet, NULL, NULL, NULL)) {
            qCritical() << "selectFdSet" << strerror(errno);
        }
        if (FD_ISSET(greFd, &fdSet)) {
            qDebug().noquote() << "Rawsock In greFd";
            addrLen = sizeof(greAddr);
            ssize_t dataLen = recvfrom(greFd, buf, bufLen, 0, (sockaddr*)&greAddr, &addrLen);  // 收到服务器发来的gre
            if (0 > dataLen) {
                qCritical() << "recvfromGre" << strerror(errno);  
                continue;
            }
            QHostAddress dst = QHostAddress(rawDecodeUint32(buf, 16));
            quint16 callId = rawDecodeUint16(buf, 26);

            qDebug().noquote() << "recvfromGre" << sockAddr(&greAddr, false) << "data" << dataLen << "callId" << callId << "proto" << (quint8)buf[9] << "dst" << dst.toString();
            dataLen = sendto(udpFd, buf, dataLen, 0, (sockaddr*)&gUdpAddr, sizeof(gUdpAddr));   // 通过udp回发给本机，等待udpReadyRead后回发给LRP
            // send UDP data which has not been connected
            if (0 > dataLen) {
                qCritical() << "sendtoUdp" << sockAddr(&gUdpAddr, true) << "err" << strerror(errno);
            }
        }
        if (FD_ISSET(udpFd, &fdSet)) {
            qDebug().noquote() << "Rawsock In udpFd";
            addrLen = sizeof(udpAddr);
            ssize_t dataLen = recvfrom(udpFd, buf, bufLen, 0, (sockaddr*)&udpAddr, &addrLen);  //收到UDP发来的GRE，接下来通过rawsock把GRE发送给pptpd服务器
            if (0 > dataLen) {
                qCritical() << "recvfromUdp" << strerror(errno);
                continue;
            }
            QHostAddress dst = QHostAddress(rawDecodeUint32(buf, 0));
            quint16 callId = rawDecodeUint16(&buf[4], 6);
            qDebug().noquote() << "recvfromUdp" << sockAddr(&udpAddr, true) << "data" << dataLen << "callId" << callId << "dst" << dst.toString();
            memset(&greAddr, 0, sizeof(greAddr));
            greAddr.sin_family = AF_INET;
            greAddr.sin_addr.s_addr = htonl(rawDecodeUint32(buf, 0));
            dataLen = sendto(greFd, &buf[4], dataLen - 4, 0, (sockaddr*)&greAddr, sizeof(greAddr));  // 将gre通过grefd对应的rawsock发送给服务器
            if (0 > dataLen) {
                qCritical() << "sendtoGre" << sockAddr(&greAddr, false) << "err" << strerror(errno);
            }
        }
    }
    close(greFd);
    close(udpFd);
}

Server::Server(QObject *parent) : QObject(parent)
{
}

Server::~Server()
{
}
//1
bool Server::init()
{
    mCallId = 0;

    mTcpServer = new QTcpServer(this);
    connect(mTcpServer, &QTcpServer::newConnection, this, &Server::tcpNewConnection);
    if (!mTcpServer->listen(QHostAddress::AnyIPv4, 3723)) {  // waiting for the lrp connection
        qDebug().noquote() << mTcpServer->serverError() << mTcpServer->errorString();
        return false;
    }
    qInfo().noquote() << "tcpListen" << mTcpServer->serverAddress().toString() + ":" + QString::number(mTcpServer->serverPort());

    mUdpSocket = new QUdpSocket(this);
    connect(mUdpSocket, &QUdpSocket::readyRead, this, &Server::udpReadyRead);
    if (!mUdpSocket->bind(QHostAddress(QHostAddress::LocalHost))) {
        qCritical().noquote() << mUdpSocket->errorString();
        return false;
    }
    qInfo().noquote() << "udpBind" << mUdpSocket->localAddress().toString() + ":" + QString::number(mUdpSocket->localPort());
    memset(&gUdpAddr, 0, sizeof(gUdpAddr));
    gUdpAddr.sin_family = AF_INET;
    gUdpAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    gUdpAddr.sin_port = htons(mUdpSocket->localPort());

    mRawsockThread = new RawsockThread(this);
    connect(mRawsockThread, &RawsockThread::finished, mRawsockThread, &QObject::deleteLater);
    mRawsockThread->start();

    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &Server::timerTimeout);
    timer->start(1000);
    return true;
}

#define PPTP_CALL(type) case pptpType_##type: pptpRecv_##type(link); break

void Server::pptpRecv(Link *link)
{
    Link *peer = link->peer;
    bool peerSend = false;
    while (pptpLen_msgLen < link->dataRx.size()) {
        quint16 msgLen = rawDecodeUint16(link->dataRx.constData(), 0);
        LINK_DBG(link) << "msgLen123" << msgLen;
        if (link->dataRx.size() < msgLen) {
            break;
        }
        const char *buf = link->dataRx.constData();
        quint16 pptpMsgType = rawDecodeUint16(buf, pptpPos_pptpMsgType);
        if (2 == pptpMsgType) {  // datamsg
            quint16 callId = rawDecodeUint16(&buf[4], 6);   // here we should change 6 to 26, then we can get the right call id
                                                            // but on the bottom we get rid of the ip header, then here the call id starts at the 6 bytes
															
															// 之后当我在对方节点发送datamsg之前 //把ip包头给去掉了，此时只需要从第4个字节开始向后寻第6个字节即得到callId
															
            LINK_DBG(link) << "pptpRecv" << "dataMsg" << "data" << msgLen << "callId" << callId;
            QString linkGre = link->tcp->peerAddress().toString() + ":" + QString::number(callId);
            Link *link = mLinkHashGre.value(linkGre, NULL);
            if (NULL == link) {
                LINK_CRT(link) << "pptpRecv " << "errLinkGre" << linkGre;
            } else {  // 用UDP 发送给本机
                rawEncodeUint32(link->dataRx.data(), 0, link->peer->tcp->peerAddress().toIPv4Address());
                rawEncodeUint16(link->dataRx.data(), 10, peer->callIdRx);
                mUdpSocket->writeDatagram(buf, msgLen, QHostAddress("127.0.0.1"), gWorkUdpPort);

            }
            link->dataRx.remove(0, msgLen);
            continue;
        }
        if (1 != pptpMsgType) {
            qCritical().noquote() << "errMsgType:" << pptpMsgType;
            link->dataRx.remove(0, msgLen);
            link->tcp->abort();
            return;
        }
        else {
            LINK_DBG(link) << "contrlMsg";
        }
        quint16 ctrlMsgType = rawDecodeUint16(buf, pptpPos_ctrlMsgType);
        LINK_DBG(link) << "ctrlMsgType" << ctrlMsgType;
        switch (ctrlMsgType) {
        PPTP_CALL(startCtrlConnRequest);
        PPTP_CALL(startCtrlConnReply);
        PPTP_CALL(stopCtrlConnRequest);
        PPTP_CALL(stopCtrlConnReply);
        PPTP_CALL(echoRequest);
        PPTP_CALL(echoReply);

        PPTP_CALL(outCallRequest);
        PPTP_CALL(outCallReply);

        PPTP_CALL(inCallRequest);
        PPTP_CALL(inCallReply);
        PPTP_CALL(inCallConnected);
        PPTP_CALL(callClearRequest);
        PPTP_CALL(callDisconnectNotify);
        PPTP_CALL(wanErrorNotify);
        PPTP_CALL(setLinkInfo);
        }
        peerSend = true;
        peer->dataTx.append(link->dataRx.left(msgLen));
        link->dataRx.remove(0, msgLen);
    }
    if (peerSend) {
        LINK_DBG(link) << "tx" << peer->dataTx.size();
        tcpSend(peer);
    }
}

void Server::pptpRecv_callClearRequest(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_callDisconnectNotify(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_echoReply(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_echoRequest(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_inCallConnected(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_inCallReply(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_inCallRequest(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_outCallReply(Link *link)
{
    quint16 callId     = rawDecodeUint16(link->dataRx.constData(), pptpPos_outCallReply_callId);
    quint16 peerCallId = rawDecodeUint16(link->dataRx.constData(), pptpPos_outCallReply_peerCallId);
    LINK_INF(link) << "outCallReply" << "callId" << callId << "peerCallId" << peerCallId;
    link->callIdRx = callId;
    if (peerCallId != link->callIdTx) {
        LINK_CRT(link) << "errPeerCallId" << peerCallId << "callIdTx" << link->callIdTx;
    }
    Link *peer = link->peer;
    peer->callIdTx = callId;
    rawEncodeUint16(link->dataRx.data(), pptpPos_outCallReply_peerCallId, peer->callIdRx);
    LINK_INF(peer) << "sending peerCallId" << peer->callIdRx;

    QString linkGre = link->tcp->peerAddress().toString() + ":" + QString::number(peerCallId);
    mLinkHashGre.insert(linkGre, link);

    QString peerGre = peer->tcp->peerAddress().toString() + ":" + QString::number(callId);
    mLinkHashGre.insert(peerGre, peer);
}

void Server::pptpRecv_outCallRequest(Link *link)
{
    quint16 callId = rawDecodeUint16(link->dataRx.constData(), pptpPos_outCallRequest_callId);
    quint16 callSn = rawDecodeUint16(link->dataRx.constData(), pptpPos_outCallRequest_CallSn);
    LINK_INF(link) << "outCallRequest" << "callId" << callId << "callSn" << callSn;
    link->callIdRx = callId;
    Link *peer = link->peer;
    peer->callIdTx = callId;

    //  Here I changed the callIdTx


    LINK_INF(link) << "outCallRequest peer" << "callIdTx" << peer->callIdTx;
    rawEncodeUint16(link->dataRx.data(), pptpPos_outCallRequest_callId, peer->callIdTx);
}

void Server::pptpRecv_setLinkInfo(Link *link)
{
    quint16 peerCallId = rawDecodeUint16(link->dataRx.constData(), pptpPos_setLinkInfo_peerCallId);
    LINK_INF(link) << "setLinkInfo" << "peerCallId" << peerCallId;
}

void Server::pptpRecv_startCtrlConnReply(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_startCtrlConnRequest(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_stopCtrlConnReply(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_stopCtrlConnRequest(Link *link)
{
    LINK_INF(link);
}

void Server::pptpRecv_wanErrorNotify(Link *link)
{
    LINK_INF(link);
}

QString Server::tcpAddr(QTcpSocket *tcp)
{
    return tcp->peerAddress().toString() + ":" + QString::number(tcp->peerPort());
}

void Server::tcpBytesWritten(qint64 bytes)
{
    QTcpSocket *tcp = qobject_cast<QTcpSocket*>(sender());
    qDebug().noquote() << tcpAddr(tcp) << "bytes" << bytes;
    LinkHash::iterator itr = mLinkHash.find(tcp);
    Link *link = itr.value();
    tcpSend(link);
}

void Server::tcpConnected()
{
    QTcpSocket *tcp = qobject_cast<QTcpSocket*>(sender());
    qWarning().noquote() << tcpAddr(tcp);
    LinkHash::iterator itr = mLinkHash.find(tcp);
    Link *link = itr.value();
    tcpSend(link);
}

void Server::tcpDisconnected()
{
    QTcpSocket *tcp = qobject_cast<QTcpSocket*>(sender());
    qWarning().noquote() << tcpAddr(tcp);
}

void Server::tcpError(QAbstractSocket::SocketError error)
{
    QTcpSocket *tcp = qobject_cast<QTcpSocket*>(sender());
    qDebug().noquote() << tcpAddr(tcp) << error;
}

void Server::tcpInit(QTcpSocket *tcp)
{
    connect(tcp, &QTcpSocket::bytesWritten, this, &Server::tcpBytesWritten);
    connect(tcp, &QTcpSocket::connected, this, &Server::tcpConnected);
    connect(tcp, &QTcpSocket::disconnected, this, &Server::tcpDisconnected);
    connect(tcp, &QTcpSocket::disconnected, tcp, &QTcpSocket::deleteLater);
    connect(tcp, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(tcpError(QAbstractSocket::SocketError))); // duplicated error() method fail compiling
    connect(tcp, &QTcpSocket::readyRead, this, &Server::tcpReadyRead);
    connect(tcp, &QTcpSocket::stateChanged, this, &Server::tcpStateChanged);
}
//2
void Server::tcpNewConnection()
{
    while (mTcpServer->hasPendingConnections()) {
        QTcpSocket *tcp = mTcpServer->nextPendingConnection();
        qInfo().noquote() << tcpAddr(tcp);
        tcpInit(tcp);
        Link *link = new Link;
        link->tcp = tcp;
        link->peer = new Link;
        link->peer->tcp = new QTcpSocket(this);
        tcpInit(link->peer->tcp);
        link->peer->tcp->connectToHost("127.0.0.1", 1723);
        link->peer->peer = link;
        mLinkHash.insert(tcp, link);
        mLinkHash.insert(link->peer->tcp, link->peer);
    }
}

void Server::tcpReadyRead()
{
    QTcpSocket *tcp = qobject_cast<QTcpSocket*>(sender());
    LinkHash::iterator itr = mLinkHash.find(tcp);
    Link *link = itr.value();
    link->dataRx.append(tcp->readAll());
    qDebug().noquote() << tcpAddr(tcp) << "rx" << link->dataRx.size();
    pptpRecv(link);
}

void Server::tcpSend(Link *link)
{
    if (QAbstractSocket::ConnectedState == link->tcp->state()) {
        qint64 sent = link->tcp->write(link->dataTx);
        if (0 < sent) {
            link->dataTx.remove(0, sent);
            qDebug().noquote() << tcpAddr(link->tcp) << "tx" << link->dataTx.size();
        }
    }
}

void Server::tcpStateChanged(QAbstractSocket::SocketState state)
{
    QTcpSocket *tcp = qobject_cast<QTcpSocket*>(sender());
    qDebug().noquote() << tcpAddr(tcp) << state;
    if (QAbstractSocket::UnconnectedState!=state) {
        return;
    }
    LinkHash::iterator itr = mLinkHash.find(tcp);
    Link *link = itr.value();
    mLinkHash.erase(itr);
    QString linkGre = tcp->peerAddress().toString() + ":" + QString::number(link->callIdTx);
    mLinkHashGre.remove(linkGre);
    if (Link *peer = link->peer) {
        peer->peer = NULL;
        peer->tcp->abort();
    }
    delete link;
}

void Server::timerTimeout()
{
}

void Server::udpReadyRead()
{
    char buf[65536];
    qint64 bufLen = sizeof(buf);

    QHostAddress udpSrcAddr;
    quint16 udpSrcPort;
    while (mUdpSocket->hasPendingDatagrams()) {
        qint64 dataLen = mUdpSocket->readDatagram(&buf[4], bufLen - 4, &udpSrcAddr, &udpSrcPort);

        quint16 callId = rawDecodeUint16(&buf[4], 26);
        QHostAddress greSrc = QHostAddress(rawDecodeUint32(&buf[4], 12));
        QHostAddress greDst = QHostAddress(rawDecodeUint32(&buf[4], 16));
        qDebug().noquote() << "udpReadyRead debug, udp sourse address is " << udpSrcAddr.toString() + ":" + QString::number(udpSrcPort) << "data" << dataLen << "callId" << callId << "proto" << (quint8)buf[4+9] << "src" << greSrc.toString() << "dst" << greDst.toString();
        QString linkGre = greSrc.toString() + ":" + QString::number(callId);
        Link *link = mLinkHashGre.value(linkGre, NULL);
        if (NULL == link) {
            qCritical() << "udpReadyRead " << "errLinkGre" << linkGre;
            continue;
        }

		// 我们把udpReadyRead时候要发给下一跳的TCP包 数据部分的IP头给跳过
        memcpy(&buf[4], &buf[24], dataLen);  // Here we jump the first 20 bytes ip header and send the right gre msg 
        Link *peer = link->peer;
        rawEncodeUint16(buf, 0, 4 + dataLen - 20); // Length
        rawEncodeUint16(buf, 2, 2); // PPTP Message Type
        peer->dataTx.append(buf, 4 + dataLen - 20);
        tcpSend(peer);
    }
}

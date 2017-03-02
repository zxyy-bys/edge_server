/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <errno.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>

const char* sample =
"POST /document/u/0/d/18TXk0UI5pJdEBsT9sAdHyPHCxxe7xLCyhKFAtq70TZo/save?id=18TXk0UI5pJdEBsT9sAdHyPHCxxe7xLCyhKFAtq70TZo&sid=790421622421afd6&c=1&w=1&smv=2&token=AC4w5VgGNPzUiO-KUfPoF_Xz0QmZgsyUkg%3A1488316923016 HTTP/1.1\r\n"
"Host: docs.google.com\r\n"
"Connection: keep-alive\r\n"
"Content-Length: 517\r\n"
"X-Build: kix_2017.08-Tue_RC04\r\n"
"X-Same-Domain: 1\r\n"
"Origin: https://docs.google.com\r\n"
"X-Rel-Id: 135.46b9d38.s\r\n"
"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.91 Safari/537.36\r\n"
"Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n"
"X-Chrome-UMA-Enabled: 1\r\n"
"X-Chrome-Connected: id=111122620937263590269,mode=0,enable_account_consistency=true\r\n"
"Accept: */*\r\n"
" Referer: https://docs.google.com/document/d/18TXk0UI5pJdEBsT9sAdHyPHCxxe7xLCyhKFAtq70TZo/edit\r\n"
" Accept-Encoding: gzip, deflate, br\r\n"
" Accept-Language: en-US,en;q=0.8\r\n"
" Cookie: S=documents=q8a1dgODWNpH8B8KZzECpCJ0QpVDPIKF; SID=ZAQkPVIhK5xiebypIkXSb0koKhvctoCVvoicCu-jW5oFyVxjPtnx4oVUYb0U5ZEBQRb4SA.; HSID=Atd1pSV1erZ9q2RrJ; SSID=AMCYUP1U4lfAWS2Mt; APISID=9XTYwljWtzJ-rttO/AZcj5eIB8ryu4nSgy; SAPISID=KKZAp2KqE_-dIdh3/AggcGoVZZx7AalWmU; WRITELY_SID=ZAQkPUy7ZiPLlqUIyHwhQFkYbhVwb_E1JmSzUvuWWJZbN6Mcm73K2RTpu7BJJaToIXEOXQ.; S=explorer=F3MxOn0nSxzN0Q2yGngZrUUduxinHKKB; NID=98=5UaPqIcrUwY_xycmRncTenmJ_Zld0ppWipCPNnBlC3HIRslZ6UbTFMy5f4ud8PmRddAYt90ECoiweLgS_MOl_CrhItfod4PrxPNeZ90q4wOTa77aO_zt2uRC7QlwuCrv5tU7tRxiZ7M_YGNj3aflIy6XQvZdmGTq3X8SIpXZ200mrhCtMkCiRTyiPRN4HQxo0q8JiP_TFpQ40UQ_CgGPjsqT; llbcs=3; lbcs=2\r\n\r\n" "rev=1&bundles=%5B%7B%22commands%22%3A%5B%7B%22ty%22%3A%22is%22%2C%22ibi%22%3A1%2C%22s%22%3A%22Ty%22%7D%2C%7B%22ty%22%3A%22as%22%2C%22st%22%3A%22text%22%2C%22si%22%3A1%2C%22ei%22%3A2%2C%22sm%22%3A%7B%22ts_bd_i%22%3Atrue%2C%22ts_fs_i%22%3Atrue%2C%22ts_ff_i%22%3Atrue%2C%22ts_it_i%22%3Atrue%2C%22ts_sc_i%22%3Atrue%2C%22ts_st_i%22%3Atrue%2C%22ts_tw%22%3A400%2C%22ts_un_i%22%3Atrue%2C%22ts_va_i%22%3Atrue%2C%22ts_bgc_i%22%3Atrue%2C%22ts_fgc_i%22%3Atrue%7D%7D%5D%2C%22sid%22%3A%22790421622421afd6%22%2C%22reqId%22%3A0%7D%";

typedef struct pxy_conn_ctx{
    SSL * ssl;
}pxy_conn_ctx_t;

static
pxy_conn_ctx_t *pxy_conn_ctx_init()
{
    pxy_conn_ctx_t * ctx = malloc(sizeof(pxy_conn_ctx_t));
    if(ctx == NULL){
        perror("malloc ctx failed\n");
        exit(-1);
    }
    ctx->ssl = NULL;
    return ctx;
}

void pxy_conn_ctx_free(pxy_conn_ctx_t * ctx)
{
    if(ctx->ssl != NULL){
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
    }
}
void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int connect_to_googledocs(pxy_conn_ctx_t*,char*, size_t);
//listen to specific port
/* int client_side_listener()
 * {
 *      int sockfd, newsockfd, portno;
 *      socklen_t clilen;
 *      char buffer[10000];
 *      struct sockaddr_in serv_addr, cli_addr;
 *      int n;
 *      sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *      if (sockfd < 0)
 *         error("ERROR opening socket");
 *      bzero((char *) &serv_addr, sizeof(serv_addr));
 *      portno = 1234;
 *      serv_addr.sin_family = AF_INET;
 *      serv_addr.sin_addr.s_addr = INADDR_ANY;
 *      serv_addr.sin_port = htons(portno);
 *      if (bind(sockfd, (struct sockaddr *) &serv_addr,
 *               sizeof(serv_addr)) < 0)
 *               error("ERROR on binding");
 *      listen(sockfd,5);
 *      clilen = sizeof(cli_addr);
 *      newsockfd = accept(sockfd,
 *                  (struct sockaddr *) &cli_addr,
 *                  &clilen);
 *      if (newsockfd < 0)
 *           error("ERROR on accept");
 *      bzero(buffer,10000);
 *
 *      do{
 *          n = read(newsockfd,buffer,10000);
 *          if (n < 0) error("ERROR reading from socket");
 *          printf("Here is the message: %s\n",buffer);
 *          //     n = write(newsockfd,"I got your message",18);
 *          //     if (n < 0) error("ERROR writing to socket");
 *          pxy_conn_ctx_t *ctx = pxy_conn_ctx_init();
 *          connect_to_googledocs(ctx,buffer, n);
 *      }while(n > 0);
 *      close(newsockfd);
 *      close(sockfd);
 *      return 0;
 * } */

void edge_listener_acceptcb(UNUSED struct evconnlistener *listener,);

struct evconnlistener* edge_listener_setup(struct event_base *evbase)
{
    evutil_socket_t fd;
    int rv;
    int on = 1;
    fd = socket(AF_INET, SOCK_STREAM,0);
    if(fd == -1){
        error("create socket failed\n");
        evutil_closesocket(fd);
    }
    rv = evutil_make_socket_nonblocking(fd);
    if(fd == -1){
        error("set socket non-block failed\n");
        evutil_closesocket(fd);
    }

    rv = setsockopt(fd, SOL_SOCKET,SO_KEEPALIVE,(void*)&on, sizeof(on));
    if(fd == -1){
        fprintf(stderr,"set socket opt failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return NULL;
    }
//    rv = evutil_make_listen_socket_reusable(fd);
    if(fd == -1){
        fprintf(stderr,"set socket reusable failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return NULL;
    }

    struct sockaddr_in serv_addr, cli_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(1234);
    rv = bind(fd,(struct sockaddr *) &serv_addr,sizeof(struct sockaddr));

    if(rv == -1){
        fprintf(stderr,"bind socket failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return NULL;
    }

    struct evconnlistener* evcl = evconnlistener_new(evbase,edge_listener_acceptcb, NULL,LEV_OPT_CLOSE_ON_FREE,1024,fd);

    if(evcl == NULL){
        perror("evconnlistener_new failed %s\n",strerror(errno));
        evutil_closesocket(fd);
        return;
    }
    return evcl;
}

//Connect to google doc.
//
void init_OpenSSL()
{
    if(!SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed! \n");
    }
    SSL_load_error_strings();
}

SSL_CTX * setup_client_ctx()
{
    SSL_CTX* ctx;
    ctx = SSL_CTX_new(SSLv23_method());


    SSL_CTX_set_options(ctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
    SSL_CTX_set_options(ctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /*  SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /*  SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /*  SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif /*  SSL_OP_NO_TICKET */
/* #ifdef SSL_OP_NO_COMPRESSION
 *     SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
 * #endif [>  SSL_OP_NO_COMPRESSION <]
 *
 * #ifdef SSL_OP_NO_SSLv2
 * #ifdef WITH_SSLV2
 * #endif [>  WITH_SSLV2 <]
 *         SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
 * #ifdef WITH_SSLV2
 * #endif [>  WITH_SSLV2 <]
 * #endif [>  !SSL_OP_NO_SSLv2 <]
 * #ifdef SSL_OP_NO_SSLv3
 *         SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
 * #endif [>  SSL_OP_NO_SSLv3 <]
 * #ifdef SSL_OP_NO_TLSv1
 *         SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
 * #endif [>  SSL_OP_NO_TLSv1 <]
 * #ifdef SSL_OP_NO_TLSv1_1
 *     SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
 * #endif [>  SSL_OP_NO_TLSv1_1 <]
 * #ifdef SSL_OP_NO_TLSv1_2
 *     SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
 * #endif [>  SSL_OP_NO_TLSv1_2 <] */

    SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
    return ctx;
}

int send_request(SSL *ssl, char * data, size_t length)
{
    int err;
    //char* sample = "sfsdf";
    err = SSL_write(ssl,data,length);
    fprintf(stderr,"after ssl_write %d\n",err);
    if(err < 0 ){
         perror("Error write request error\n");
         return 0;
     }
    char buff[10000] = {'\0'};
    int n = 0;
    do{
        n = SSL_read(ssl, buff + n, 10000);
        fprintf(stderr,"response %s\n", buff);
    }while(n > 0);
    return 1;
}

int connect_to_googledocs(pxy_conn_ctx_t* ctx, char * data, size_t length)
{
    if(ctx->ssl == NULL){
        BIO * conn;
        SSL * ssl;
        SSL_CTX * sslctx;
        init_OpenSSL();
        int error;
        //    seed_prng();
        sslctx = setup_client_ctx();

        conn = BIO_new_connect("4.docs.google.com:443");
//        conn = BIO_new_connect("172.217.2.14:443");
        if(!conn)
            perror("Error creating connection BIO\n");
        if((error = BIO_do_connect(conn)) <= 0){
            perror("Error connecting to remote machine\n");
        }
        fprintf(stderr,"BIO_do_connect %d\n",error);
        if(!(ssl = SSL_new(sslctx)))
            perror("Error creating an SSL context\n");
        SSL_set_bio(ssl,conn,conn);
        if( (error = SSL_connect(ssl)) <= 0 ){
            perror("Error connecting SSL google docs\n");
        }

        fprintf(stderr,"SSL_connect %d\n",error);
        SSL_CTX_free(sslctx);
        ctx->ssl = ssl;
    }
    send_request(ctx->ssl,data,length);
    return 0;
}

int main()
{
    /* fprintf(stderr,"start connecting to google docs\n");
     * connect_to_googledocs();
     * fprintf(stderr,"finish connecting to google docs\n"); */
    client_side_listener();

}

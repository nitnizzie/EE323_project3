/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"


enum { LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT, CLOSED,
    CLOSE_WAIT, LAST_ACK, CLOSING };    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    tcp_seq rcvd_seq;
    tcp_seq rcvd_ack;
    tcp_seq rcvd_win;
    size_t  rcvd_len;

    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    ctx->connection_state = LISTEN;

    // Client active open
    if (is_active == TRUE) {
        //create SYN packet
        STCPHeader *header = (STCPHeader *) calloc(1, sizeof(STCPHeader));
        header->th_seq = htonl(ctx->initial_sequence_num);
        header->th_ack = htonl(0);
        header->th_off = sizeof(STCPHeader)/4;
        header->th_flags = TH_SYN;
        header->th_win = htons(3072);

        //send SYN packet to server
        if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
            errno = ECONNREFUSED;
            free(header);
            free(ctx);
            return;
        }
        ctx->connection_state = SYN_SENT;

        //wait for SYN-ACK packet from server
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);

        STCPHeader *packet = (STCPHeader *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t numBytes;
        if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < sizeof(STCPHeader)) {
            errno = ECONNREFUSED;
            free(header);
            free(packet);
            free(ctx);
            return;
        }
        if (packet->th_flags != (TH_SYN | TH_ACK)) {
            errno = ECONNREFUSED;
            free(header);
            free(packet);
            free(ctx);
            return;
        }
        ctx->rcvd_seq = ntohl(packet->th_seq);
        ctx->rcvd_ack = ntohl(packet->th_ack);
        ctx->rcvd_win = ntohs(packet->th_win);
        ctx->rcvd_len = numBytes - sizeof(STCPHeader);

        ctx->connection_state = ESTABLISHED;

        //create ACK packet
        header->th_seq = htonl(ctx->rcvd_ack);
        header->th_ack = htonl(ctx->rcvd_seq + 1);
        header->th_flags = TH_ACK;
        header->th_off = sizeof(STCPHeader)/4;
        header->th_win = htons(3072);

        //send ACK packet to server
        if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
            errno = ECONNREFUSED;
            free(header);
            free(packet);
            free(ctx);
            return;
        }
        ctx->rcvd_seq += 1;

        free(header);
        free(packet);
    }
    // Server passive open
    else {
        //wait for SYN packet from client
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);

        STCPHeader *packet = (STCPHeader *)calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t numBytes;
        if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
            errno = ECONNREFUSED;
            free(packet);
            free(ctx);
            return;
        }
        if (packet->th_flags != TH_SYN) {
            errno = ECONNREFUSED;
            free(packet);
            free(ctx);
            return;
        }
        ctx->rcvd_seq = ntohl(packet->th_seq);
        ctx->rcvd_ack = ntohl(packet->th_ack);
        ctx->rcvd_win = ntohs(packet->th_win);
        ctx->rcvd_len = numBytes - sizeof(STCPHeader);

        ctx->connection_state = SYN_RCVD;

        //create SYN-ACK packet
        STCPHeader *header = (STCPHeader *) calloc(1, sizeof(STCPHeader));
        header->th_seq = htonl(ctx->initial_sequence_num);
        header->th_ack = htonl(ctx->rcvd_seq + 1);
        header->th_flags = TH_SYN | TH_ACK;
        header->th_off = sizeof(STCPHeader)/4;
        header->th_win = htons(3072);

        //new socket sends SYN-ACK packet to client
        if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
            errno = ECONNREFUSED;
            free(header);
            free(packet);
            free(ctx);
            return;
        }

        //wait for ACK packet from client
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);

        if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
            errno = ECONNREFUSED;
            free(header);
            free(packet);
            free(ctx);
            return;
        }
        if (packet->th_flags != TH_ACK) {
            errno = ECONNREFUSED;
            free(header);
            free(packet);
            free(ctx);
            return;
        }
        ctx->rcvd_seq = ntohl(packet->th_seq);
        ctx->rcvd_ack = ntohl(packet->th_ack);
        ctx->rcvd_win = ntohs(packet->th_win);
        ctx->rcvd_len = numBytes - sizeof(STCPHeader);

        ctx->connection_state = ESTABLISHED;

        free(header);
        free(packet);
    }

    stcp_unblock_application(sd);
    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */

            //mywrite() called
            char* payload = (char *)calloc(1, STCP_MSS);
            size_t payload_size;
            if((payload_size = stcp_app_recv(sd, payload, STCP_MSS)) < 0) {
                errno = ECONNREFUSED;
                free(payload);
                free(ctx);
                return;
            }
            // printf("payload: %ssize: %d\n", payload, payload_size);

            //create ACK packet
            STCPHeader *packet = (STCPHeader *)calloc(1, sizeof(STCPHeader) + payload_size);
            packet->th_seq = htonl(ctx->rcvd_ack);
            packet->th_ack = htonl(ctx->rcvd_seq + ctx->rcvd_len);
            packet->th_flags = TH_ACK;
            packet->th_off = sizeof(STCPHeader)/4;
            packet->th_win = htons(3072);

            memcpy((void*)packet + sizeof(STCPHeader), payload, payload_size);

            //send packet to peer
            if(stcp_network_send(sd, (void *)packet, sizeof(STCPHeader) + payload_size, NULL) < 0) {
                errno = ECONNREFUSED;
                free(payload);
                free(packet);
                free(ctx);
                return;
            }

            //wait for ACK packet from peer
            stcp_wait_for_event(sd, NETWORK_DATA, NULL);

            char *buffer = (char *)calloc(1, sizeof(STCPHeader) + STCP_MSS);
            packet = (STCPHeader *)buffer;

            ssize_t numBytes;
            if((numBytes = stcp_network_recv(sd, (void *)buffer, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
                errno = ECONNREFUSED;
                free(payload);
                free(packet);
                free(ctx);
                return;
            }
            ctx->rcvd_seq = ntohl(packet->th_seq);
            ctx->rcvd_ack = ntohl(packet->th_ack);
            ctx->rcvd_win = ntohs(packet->th_win);
            ctx->rcvd_len = numBytes - sizeof(STCPHeader);

            // char * rcvd_payload = (char *)calloc(1, ctx->rcvd_len);
            // memcpy(rcvd_payload, buffer + sizeof(STCPHeader), ctx->rcvd_len);
            // payload[ctx->rcvd_len] = '\0';

            // printf("rcvd: %d\t%d\t%ld\t%d\n", ctx->rcvd_seq, ctx->rcvd_ack, ctx->rcvd_len, ctx->rcvd_win);
            // printf("rcvd_payload: %s\n", rcvd_payload); 

            free(payload);
            free(packet);
        }
        else if (event & NETWORK_DATA)
        {
            //wait for data from peer
            char *buffer = (char *)calloc(1, sizeof(STCPHeader) + STCP_MSS);
            STCPHeader *packet = (STCPHeader *)buffer;
            ssize_t numBytes;
            if((numBytes = stcp_network_recv(sd, (void *)buffer , sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
                errno = ECONNREFUSED;
                free(packet);
                free(ctx);
                return;
            }
            ctx->rcvd_seq = ntohl(packet->th_seq);
            ctx->rcvd_ack = ntohl(packet->th_ack);
            ctx->rcvd_win = ntohs(packet->th_win);
            ctx->rcvd_len = numBytes - sizeof(STCPHeader);

            // char* payload = (char *)calloc(1, STCP_MSS);
            // memcpy(payload, buffer + sizeof(STCPHeader), ctx->rcvd_len);
            // payload[ctx->rcvd_len] = '\0';

            // printf("rcvd: %d\t%d\t%ld\t%d\n", ctx->rcvd_seq, ctx->rcvd_ack, ctx->rcvd_len, ctx->rcvd_win);
            // printf("payload: %ssize: %d\n", payload, ctx->rcvd_len);

            //check if connection is ESTABLISHED
            if(ctx->connection_state != ESTABLISHED) {
                errno = ECONNREFUSED;
                free(packet);
                free(ctx);
                return;
            }
            
            //check if packet is FIN-ACK
            if(packet->th_flags == (TH_FIN | TH_ACK)) {
                ctx->connection_state = CLOSE_WAIT;

                //notifiy FIN-ACK received
                stcp_fin_received(sd);

                //create ACK packet
                STCPHeader *header = (STCPHeader *) calloc(1, sizeof(STCPHeader));
                header->th_seq = htonl(ctx->rcvd_ack);
                header->th_ack = htonl(ctx->rcvd_seq + 1);
                header->th_flags = TH_ACK;
                header->th_off = sizeof(STCPHeader)/4;
                header->th_win = htons(3072);

                //send ACK packet to client
                if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                ctx->connection_state = LAST_ACK;

                //create FIN-ACK packet
                header->th_seq = htonl(ctx->rcvd_ack);
                header->th_ack = htonl(ctx->rcvd_seq + 1);
                header->th_flags = TH_FIN | TH_ACK;
                header->th_off = sizeof(STCPHeader)/4;
                header->th_win = htons(3072);

                //send FIN-ACK packet to client 
                if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }

                //wait for ACK packet from client
                stcp_wait_for_event(sd, NETWORK_DATA, NULL);

                if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                if (packet->th_flags != TH_ACK) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                ctx->rcvd_seq = ntohl(packet->th_seq);
                ctx->rcvd_ack = ntohl(packet->th_ack);
                ctx->rcvd_win = ntohs(packet->th_win);
                ctx->rcvd_len = numBytes - sizeof(STCPHeader);

                ctx->connection_state = CLOSED;
                ctx->done = TRUE;

                free(header);
                free(packet);
                return;
            }
            //regular data packet
            else {
                //myread() called
                stcp_app_send(sd, ((char *)packet + sizeof(STCPHeader)), (size_t)ctx->rcvd_len);
                
                //create ACK packet
                STCPHeader *header = (STCPHeader *) calloc(1, sizeof(STCPHeader));
                header->th_seq = htonl(ctx->rcvd_ack);
                header->th_ack = htonl(ctx->rcvd_seq + ctx->rcvd_len);
                header->th_flags = TH_ACK;
                header->th_off = sizeof(STCPHeader)/4;
                header->th_win = htons(3072);

                //send ACK packet to peer
                if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
            }
        }
        /* the application has requested to close the connection */
        else if (event & APP_CLOSE_REQUESTED)
        {
            //check if connection is ESTABLISHED
            if(ctx->connection_state != ESTABLISHED) {
                errno = ECONNREFUSED;
                free(ctx);
                return;
            }

            //create FIN-ACK packet
            STCPHeader *header = (STCPHeader *) calloc(1, sizeof(STCPHeader));
            header->th_seq = htonl(ctx->rcvd_ack);
            header->th_ack = htonl(ctx->rcvd_seq + ctx->rcvd_len);
            header->th_flags = TH_FIN | TH_ACK;
            header->th_off = sizeof(STCPHeader)/4;
            header->th_win = htons(3072);

            //send FIN-ACK packet to server
            if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
                errno = ECONNREFUSED;
                free(header);
                free(ctx);
                return;
            }

            ctx->connection_state = FIN_WAIT_1;

            //wait for ACK packet from server
            stcp_wait_for_event(sd, NETWORK_DATA, NULL);

            STCPHeader *packet = (STCPHeader *)calloc(1, sizeof(STCPHeader) + STCP_MSS);
            ssize_t numBytes;
            if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
                errno = ECONNREFUSED;
                free(header);
                free(packet);
                free(ctx);
                return;
            }
            ctx->rcvd_seq = ntohl(packet->th_seq);
            ctx->rcvd_ack = ntohl(packet->th_ack);
            ctx->rcvd_win = ntohs(packet->th_win);
            ctx->rcvd_len = numBytes - sizeof(STCPHeader);

            //simultaneous close
            if(packet->th_flags == (TH_FIN | TH_ACK)) {
                ctx->connection_state = CLOSING;

                //notifiy FIN-ACK received
                stcp_fin_received(sd);

                //create ACK packet
                header->th_seq = htonl(ctx->rcvd_ack + 1);
                header->th_ack = htonl(ctx->rcvd_seq + 1);
                header->th_flags = TH_ACK;
                header->th_off = sizeof(STCPHeader)/4;
                header->th_win = htons(3072);

                //send ACK packet to server
                if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }

                ctx->connection_state = TIME_WAIT;

                //wait for ACK packet from server
                stcp_wait_for_event(sd, NETWORK_DATA, NULL);

                if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                if (packet->th_flags != TH_ACK) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                ctx->rcvd_seq = ntohl(packet->th_seq);
                ctx->rcvd_ack = ntohl(packet->th_ack);
                ctx->rcvd_win = ntohs(packet->th_win);
                ctx->rcvd_len = numBytes - sizeof(STCPHeader);
                
            }
            else if(packet->th_flags == TH_ACK) {
                ctx->connection_state = FIN_WAIT_2;

                //wait for FIN-ACK packet from server
                stcp_wait_for_event(sd, NETWORK_DATA, NULL);

                if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                if (packet->th_flags != (TH_FIN | TH_ACK)) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
                ctx->rcvd_seq = ntohl(packet->th_seq);
                ctx->rcvd_ack = ntohl(packet->th_ack);
                ctx->rcvd_win = ntohs(packet->th_win);
                ctx->rcvd_len = numBytes - sizeof(STCPHeader);

                ctx->connection_state = TIME_WAIT;

                //notifiy FIN-ACK received
                stcp_fin_received(sd);

                //create ACK packet
                header->th_seq = htonl(ctx->rcvd_ack);
                header->th_ack = htonl(ctx->rcvd_seq + 1);
                header->th_flags = TH_ACK;
                header->th_off = sizeof(STCPHeader)/4;
                header->th_win = htons(3072);

                //send ACK packet to server
                if(stcp_network_send(sd, (void *)header, sizeof(STCPHeader), NULL) < 0) {
                    errno = ECONNREFUSED;
                    free(header);
                    free(packet);
                    free(ctx);
                    return;
                }
            }
            else {
                errno = ECONNREFUSED;
                free(header);
                free(packet);
                free(ctx);
                return;
            }

            ctx->connection_state = CLOSED;
            ctx->done = TRUE;

            free(header);
            free(packet);
            return;
        }
        else
        {
            /* this should never happen */
            assert(0);
        }            

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}




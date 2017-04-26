/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <config.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_internal.h>
#include <net_mosq.h>
#include <memory_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <tls_mosq.h>
#include <util_mosq.h>
#include <will_mosq.h>

#ifdef WITH_BRIDGE

int mqtt3_bridge_new(struct mosquitto_db *db, struct _mqtt3_bridge *bridge)
{
	struct mosquitto *new_context = NULL;
	struct mosquitto **bridges;
	char hostname[256];
	int len;
	char *id, *local_id;

	assert(db);
	assert(bridge);

	if(!bridge->remote_clientid){
		if(!gethostname(hostname, 256)){
			len = strlen(hostname) + strlen(bridge->name) + 2;
			id = _mosquitto_malloc(len);
			if(!id){
				return MOSQ_ERR_NOMEM;
			}
			snprintf(id, len, "%s.%s", hostname, bridge->name);
		}else{
			return 1;
		}
		bridge->remote_clientid = id;
	}
	if(bridge->local_clientid){
		local_id = _mosquitto_strdup(bridge->local_clientid);
		if(!local_id){
			return MOSQ_ERR_NOMEM;
		}
	}else{
		len = strlen(bridge->remote_clientid) + strlen("local.") + 2;
		local_id = _mosquitto_malloc(len);
		if(!local_id){
			return MOSQ_ERR_NOMEM;
		}
		snprintf(local_id, len, "local.%s", bridge->remote_clientid);
		bridge->local_clientid = _mosquitto_strdup(local_id);
		if(!bridge->local_clientid){
			_mosquitto_free(local_id);
			return MOSQ_ERR_NOMEM;
		}
	}

	HASH_FIND(hh_id, db->contexts_by_id, local_id, strlen(local_id), new_context);
	if(new_context){
		/* (possible from persistent db) */
		_mosquitto_free(local_id);
	}else{
		/* id wasn't found, so generate a new context */
		new_context = mqtt3_context_init(db, -1);
		if(!new_context){
			_mosquitto_free(local_id);
			return MOSQ_ERR_NOMEM;
		}
		new_context->id = local_id;
		HASH_ADD_KEYPTR(hh_id, db->contexts_by_id, new_context->id, strlen(new_context->id), new_context);
	}
	new_context->bridge = bridge;
	new_context->is_bridge = true;

	new_context->username = new_context->bridge->remote_username;
	new_context->password = new_context->bridge->remote_password;

#ifdef WITH_TLS
	new_context->tls_cafile = new_context->bridge->tls_cafile;
	new_context->tls_capath = new_context->bridge->tls_capath;
	new_context->tls_certfile = new_context->bridge->tls_certfile;
	new_context->tls_keyfile = new_context->bridge->tls_keyfile;
	new_context->tls_cert_reqs = SSL_VERIFY_PEER;
	new_context->tls_version = new_context->bridge->tls_version;
	new_context->tls_insecure = new_context->bridge->tls_insecure;
#ifdef REAL_WITH_TLS_PSK
	new_context->tls_psk_identity = new_context->bridge->tls_psk_identity;
	new_context->tls_psk = new_context->bridge->tls_psk;
#endif
#endif

	bridge->try_private_accepted = true;
	new_context->protocol = bridge->protocol_version;

	bridges = _mosquitto_realloc(db->bridges, (db->bridge_count+1)*sizeof(struct mosquitto *));
	if(bridges){
		db->bridges = bridges;
		db->bridge_count++;
		db->bridges[db->bridge_count-1] = new_context;
	}else{
		return MOSQ_ERR_NOMEM;
	}

#if defined(__GLIBC__) && defined(WITH_ADNS)
	new_context->bridge->restart_t = 1; /* force quick restart of bridge */
	return mqtt3_bridge_connect_step1(db, new_context);
#else
	return mqtt3_bridge_connect(db, new_context);
#endif
}

#if defined(__GLIBC__) && defined(WITH_ADNS)
int mqtt3_bridge_connect_step1(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	int i;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	context->state = mosq_cs_new;
	context->sock = INVALID_SOCKET;
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_session = context->bridge->clean_session;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	mqtt3_bridge_packet_cleanup(context);
	mqtt3_db_message_reconnect_reset(db, context);

	if(context->clean_session){
		mqtt3_db_messages_delete(db, context);
	}

	/* Delete all local subscriptions even for clean_session==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	mqtt3_subs_clean_session(db, context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(mqtt3_sub_add(db, context, context->bridge->topics[i].local_topic, context->bridge->topics[i].qos, &db->subs)) return 1;
		}
	}

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}
			notification_payload = '0';
			rc = _mosquitto_will_set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = _mosquitto_malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);

			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = _mosquitto_will_set(context, notification_topic, 1, &notification_payload, 1, true);
			_mosquitto_free(notification_topic);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}
	}

	_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = _mosquitto_try_connect_step1(context, context->bridge->addresses[context->bridge->cur_address].address);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	return MOSQ_ERR_SUCCESS;
}


int mqtt3_bridge_connect_step2(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = _mosquitto_try_connect_step2(context, context->bridge->addresses[context->bridge->cur_address].port, &context->sock);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	rc = _mosquitto_socket_connect_step3(context, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port, NULL, false);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	if(rc == MOSQ_ERR_CONN_PENDING){
		context->state = mosq_cs_connect_pending;
	}
	rc = _mosquitto_send_connect(context, context->keepalive, context->clean_session);
	if(rc == MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		_mosquitto_socket_close(db, context);
		return rc;
	}
}
#else

int mqtt3_bridge_connect(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc;
	int i;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	context->state = mosq_cs_new;
	context->sock = INVALID_SOCKET;
	context->last_msg_in = mosquitto_time();
	context->next_msg_out = mosquitto_time() + context->bridge->keepalive;
	context->keepalive = context->bridge->keepalive;
	context->clean_session = context->bridge->clean_session;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	mqtt3_bridge_packet_cleanup(context);
	mqtt3_db_message_reconnect_reset(db, context);

	if(context->clean_session){
		mqtt3_db_messages_delete(db, context);
	}

	/* Delete all local subscriptions even for clean_session==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	mqtt3_subs_clean_session(db, context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(mqtt3_sub_add(db, context, context->bridge->topics[i].local_topic, context->bridge->topics[i].qos, &db->subs)) return 1;
		}
	}

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}
			notification_payload = '0';
			rc = _mosquitto_will_set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = _mosquitto_malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);

			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = _mosquitto_will_set(context, notification_topic, 1, &notification_payload, 1, true);
			_mosquitto_free(notification_topic);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}
	}

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = _mosquitto_socket_connect(context, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port, NULL, false);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			_mosquitto_socket_close(db, context);
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	if(rc == MOSQ_ERR_CONN_PENDING){
		context->state = mosq_cs_connect_pending;
	}
	rc = _mosquitto_send_connect(context, context->keepalive, context->clean_session);
	if(rc == MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		_mosquitto_socket_close(db, context);
		return rc;
	}
}
#endif


void mqtt3_bridge_packet_cleanup(struct mosquitto *context)
{
	struct _mosquitto_packet *packet;
	if(!context) return;

	if(context->current_out_packet){
		_mosquitto_packet_cleanup(context->current_out_packet);
		_mosquitto_free(context->current_out_packet);
		context->current_out_packet = NULL;
	}
    while(context->out_packet){
		_mosquitto_packet_cleanup(context->out_packet);
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		_mosquitto_free(packet);
	}
	context->out_packet = NULL;
	context->out_packet_last = NULL;

	_mosquitto_packet_cleanup(&(context->in_packet));
}

/* cleanup of config information for Bridge */
void mqtt3_bridge_cleanup(struct _mqtt3_bridge *bridge)
{
	int j = 0 ;
	if(bridge->name) _mosquitto_free(bridge->name);
	if(bridge->addresses){
		for(j=0; j<bridge->address_count; j++){
			_mosquitto_free(bridge->addresses[j].address);
		}
		_mosquitto_free(bridge->addresses);
	}
	if(bridge->remote_clientid)
		_mosquitto_free(bridge->remote_clientid);
	if(bridge->remote_username)
		_mosquitto_free(bridge->remote_username);
	if(bridge->remote_password)
		_mosquitto_free(bridge->remote_password);
	if(bridge->local_clientid)
		_mosquitto_free(bridge->local_clientid);
	if(bridge->local_username)
		_mosquitto_free(bridge->local_username);
	if(bridge->local_password)
		_mosquitto_free(bridge->local_password);
	if(bridge->topics){
		for(j=0; j<bridge->topic_count; j++){
			if(bridge->topics[j].topic)
				_mosquitto_free(bridge->topics[j].topic);
			if(bridge->topics[j].local_prefix)
				_mosquitto_free(bridge->topics[j].local_prefix);
			if(bridge->topics[j].remote_prefix)
				_mosquitto_free(bridge->topics[j].remote_prefix);
			if(bridge->topics[j].local_topic)
				_mosquitto_free(bridge->topics[j].local_topic);
			if(bridge->topics[j].remote_topic)
				_mosquitto_free(bridge->topics[j].remote_topic);
		}
		_mosquitto_free(bridge->topics);
	}
	if(bridge->notification_topic)
		_mosquitto_free(bridge->notification_topic);
#ifdef WITH_TLS
	if(bridge->tls_version)
		_mosquitto_free(bridge->tls_version);
	if(bridge->tls_cafile)
		_mosquitto_free(bridge->tls_cafile);
#ifdef REAL_WITH_TLS_PSK
	if(bridge->tls_psk_identity)
		_mosquitto_free(bridge->tls_psk_identity);
	if(bridge->tls_psk)
		_mosquitto_free(bridge->tls_psk);
#endif
#endif
}

/* Copy of the config information for Bridge */
int mqtt3_bridge_copy(struct _mqtt3_bridge *dist, struct _mqtt3_bridge *org )
{
	int j = 0 ;
	memset( dist, 0x00, sizeof(struct _mqtt3_bridge) ) ;

	dist->keepalive = org->keepalive;
	dist->notifications = org->notifications;
	dist->start_type = org->start_type;
	dist->idle_timeout = org->idle_timeout;
	dist->restart_timeout = org->restart_timeout;
	dist->threshold = org->threshold;
	dist->try_private = org->try_private;
	dist->attempt_unsubscribe = org->attempt_unsubscribe;
	dist->protocol_version = org->protocol_version;


	if(org->name) dist->name = _mosquitto_strdup(org->name);
	if(org->addresses){
		dist->address_count=org->address_count;
		dist->addresses = _mosquitto_realloc(
								dist->addresses,
								sizeof(struct bridge_address)*dist->address_count);
		if(!dist->addresses){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		memset( dist->addresses, 0x00,
			sizeof(struct bridge_address)*dist->address_count ) ;
		for(j=0; j<org->address_count; j++)
		{
			dist->addresses[j].address = _mosquitto_strdup(org->addresses[j].address);
			dist->addresses[j].port = org->addresses[j].port;
		}
	}
	if(org->remote_clientid)
		dist->remote_clientid=_mosquitto_strdup(org->remote_clientid);
	if(org->remote_username)
		dist->remote_username=_mosquitto_strdup(org->remote_username);
	if(org->remote_password)
		dist->remote_password=_mosquitto_strdup(org->remote_password);
	if(org->local_clientid)
		dist->local_clientid=_mosquitto_strdup(org->local_clientid);
	if(org->local_username)
		dist->local_username=_mosquitto_strdup(org->local_username);
	if(org->local_password)
		dist->local_password=_mosquitto_strdup(org->local_password);
	if(org->topics)
	{
		dist->topic_count=org->topic_count;
		dist->topics = _mosquitto_realloc(
							dist->topics,
							sizeof(struct _mqtt3_bridge_topic)*dist->topic_count);
		if(!dist->topics){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		memset( dist->topics, 0x00,
			sizeof(struct _mqtt3_bridge_topic)*dist->topic_count ) ;
		for(j=0; j<org->topic_count; j++)
		{
			if(org->topics[j].topic)
				dist->topics[j].topic=_mosquitto_strdup(org->topics[j].topic);
			if(org->topics[j].local_prefix)
				dist->topics[j].local_prefix= _mosquitto_strdup(org->topics[j].local_prefix);
			if(org->topics[j].remote_prefix)
				dist->topics[j].remote_prefix=_mosquitto_strdup(org->topics[j].remote_prefix);
			if(org->topics[j].local_topic)
				dist->topics[j].local_topic=_mosquitto_strdup(org->topics[j].local_topic);
			if(org->topics[j].remote_topic)
				dist->topics[j].remote_topic=_mosquitto_strdup(org->topics[j].remote_topic);
		}
	}
	if(org->notification_topic)
		dist->notification_topic=_mosquitto_strdup(org->notification_topic);
#ifdef WITH_TLS
	if(org->tls_version)
		dist->tls_version=_mosquitto_strdup(org->tls_version);
	if(org->tls_cafile)
		dist->tls_cafile=_mosquitto_strdup(org->tls_cafile);
#ifdef REAL_WITH_TLS_PSK
	if(org->tls_psk_identity)
		dist->tls_psk_identity=_mosquitto_strdup(org->tls_psk_identity);
	if(org->tls_psk)
		dist->tls_psk=_mosquitto_strdup(org->tls_psk);
#endif
#endif
	return MOSQ_ERR_SUCCESS;
}

/* Connected to a re-reading and disconnection of the bridge information */
int mqtt3_bridge_reload(struct mosquitto_db *db)
{
	struct mqtt3_config config;
	int i = 0 ;
	int j = 0 ;
	struct _mqtt3_bridge * adds = NULL;
	int adds_count = 0;
	struct _mqtt3_bridge * dels = NULL;
	int dels_count = 0;

	struct _mqtt3_bridge * bridges = NULL;
	int bridges_count = 0;

	struct mosquitto **context_bridges = NULL ;
	int context_bridges_count = 0 ;

	// read config file
	mqtt3_config_init(&config);
	config.config_file=_mosquitto_strdup(db->config->config_file);
	if( mqtt3_config_read(&config, true, true))
	{
		mqtt3_config_cleanup( &config ) ;
		_mosquitto_log_printf(
			NULL, MOSQ_LOG_ERR, "Error: Unable to open configuration file.");
		return MOSQ_ERR_INVAL;
	}

	bool * check = _mosquitto_calloc( config.bridge_count, sizeof(bool) );
	memset( check, 0x00, sizeof(bool)*config.bridge_count);

	for( i = 0 ; i < db->bridge_count ; i ++ )
	{
		_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE,
			"bridge org: %d %s.",i, db->bridges[i]->bridge->name);
	}

	// confirmation of the deleted & added bridge
	for( i = 0 ; i < db->config->bridge_count ; i ++ )
	{
		bool ari = false ;
		for( j = 0 ; j < config.bridge_count ; j++ )
		{
			// Confirmed?
			if( !*(check+j) )
			{
				if( !strcmp( db->config->bridges[i].name, config.bridges[j].name ) )
				{
					// the same
					ari = true ;
					*(check+j) = true ;
					break ;
				}
			}
		}
		if( ari )
		{
			// Because there is the same thing, as it is used
		}
		else
		{
			// Disconnect because it is not in the new config -> deleted
			dels_count++;
			dels = _mosquitto_realloc(
						dels,
						dels_count*sizeof(struct _mqtt3_bridge));
			if(!dels)
			{
				_mosquitto_free(check);
				mqtt3_config_cleanup( &config ) ;
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			memset( &(dels[dels_count-1]), 0x00, sizeof(struct _mqtt3_bridge)) ;
			mqtt3_bridge_copy(
				&(dels[dels_count-1]),
				&(db->config->bridges[i]) ) ;
		}
	}

	for( i = 0 ; i < config.bridge_count ; i ++ )
	{
		if( !*(check+i) )
		{
			// Add
			adds_count++;
			adds = _mosquitto_realloc(
						adds,
						adds_count*sizeof(struct _mqtt3_bridge));
			if(!adds)
			{
				_mosquitto_free(dels);
				_mosquitto_free(check);
				mqtt3_config_cleanup( &config ) ;
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			memset( &(adds[adds_count-1]), 0x00, sizeof(struct _mqtt3_bridge)) ;
			mqtt3_bridge_copy(
				&(adds[adds_count-1]),
				&(config.bridges[i]) ) ;
		}
	}

	_mosquitto_free(check);
	mqtt3_config_cleanup( &config ) ;

	// If the error that config number and the context number is different (basic no)
	if( db->config->bridge_count != db->bridge_count )
	{
		_mosquitto_free(adds);
		_mosquitto_free(dels);
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR,
			"Error bridge config unmatch. why ?? %d!=%d",
			db->config->bridge_count, db->bridge_count);
	}
	else
	{
		if( dels_count > 0 )
		{
			// config and context area reserved for work
			bridges=_mosquitto_malloc(
						(db->config->bridge_count-dels_count)*sizeof(struct _mqtt3_bridge) );
			if(!bridges)
			{
				_mosquitto_free(adds);
				_mosquitto_free(dels);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			context_bridges=_mosquitto_malloc(
								(db->bridge_count-dels_count)*sizeof(struct mosquitto *) );
			if(!context_bridges)
			{
				_mosquitto_free(adds);
				_mosquitto_free(dels);
				_mosquitto_free(bridges);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}

			bool del = false ;
			for( i = 0 ; i < db->bridge_count ; i++ )
			{
				del = false ;
				for( j = 0 ; j < dels_count ; j ++ )
				{
					if( !strcmp( db->bridges[i]->bridge->name, dels[j].name ) )
					{
						del = true ;
						break ;
					}
				}
				if( !del )
				{
					_mosquitto_log_printf(NULL, MOSQ_LOG_INFO,
							"bridge stay: %s.",db->bridges[i]->bridge->name);

					mqtt3_bridge_copy(
						&(bridges[bridges_count]),
						db->bridges[i]->bridge ) ;

					context_bridges[context_bridges_count] = db->bridges[i];
					context_bridges[context_bridges_count]->bridge =
						&(bridges[bridges_count]) ;
					bridges_count++;
					context_bridges_count++;
				}
				else
				{
					_mosquitto_log_printf(NULL, MOSQ_LOG_INFO,
							"bridge del: %s.",db->bridges[i]->bridge->name);

					// disconnetc & clean
					mqtt3_context_cleanup(db, db->bridges[i], true);
				}
			}

			// old config clean
			for( i = 0 ; i < db->config->bridge_count ; i++ )
			{
				mqtt3_bridge_cleanup(&(db->config->bridges[i]));
			}

			// bridge config update
			_mosquitto_free(db->config->bridges);
			db->config->bridge_count=bridges_count;
			db->config->bridges = bridges ;

			// bridge context update
			_mosquitto_free(db->bridges);
			db->bridge_count=context_bridges_count ;
			db->bridges=context_bridges;

			// clean delete work area
			for( j = 0 ; j < dels_count ; j ++ )
			{
				mqtt3_bridge_cleanup(&(dels[j]));
			}
			_mosquitto_free(dels);

		}

		if( adds_count > 0 )
		{
			// To realloc the additional configuration information
			db->config->bridges=_mosquitto_realloc( db->config->bridges,
						(db->config->bridge_count+adds_count)*sizeof(struct _mqtt3_bridge) );
			if(!db->config->bridges)
			{
				_mosquitto_free(adds);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
			// Transfer the config you are using at present context
			for( i = 0 ; i < db->bridge_count ; i++ )
			{
				db->bridges[i]->bridge = &db->config->bridges[i];
			}
			// Additional bridge loop
			for( i = 0 ; i < adds_count ; i++ )
			{
				mqtt3_bridge_copy(
						&(db->config->bridges[db->config->bridge_count]),
						&(adds[i]) ) ;

				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO,
						"bridge add: %s.",
						db->config->bridges[db->config->bridge_count].name);
				db->config->bridge_count ++ ;

				// connect to add bridge
				if(mqtt3_bridge_new(
						db,
						&(db->config->bridges[db->config->bridge_count-1])))
				{
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING,
							"Warning: Unable to connect to bridge %s.",
								db->config->bridges[db->config->bridge_count-1].name);
				}
			}

			// clean add work area
			for( j = 0 ; j < adds_count ; j ++ )
			{
				mqtt3_bridge_cleanup(&(adds[j]));
			}
			_mosquitto_free(adds);
		}
	}
	for( i = 0 ; i < db->bridge_count ; i ++ )
	{
		_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE,
					"bridge new: %d %s.",i, db->bridges[i]->bridge->name);
	}
	return MOSQ_ERR_SUCCESS;
}
#endif

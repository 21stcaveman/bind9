/*
 * MongoDB BIND SDB Driver
 *
 * Copyright (C) [Hamid Maadani](https://github.com/21stcaveman) <hamid@dexo.tech>.
 *
 * $Id: dlz_mongodb_driver.c,v 1.0 2017/05/04 18:44:50 21stcaveman Exp $
 *
 * Example collection mydomain.com :
 * [
 *  { name:'mydomain.com', ttl: 259200, rdtype:'SOA', rdata:'mydomain.com. www.mydomain.com. 200309181 28800 7200 86400 28800' },
 *  { name:'mydomain.com', ttl: 259200, rdtype:'NS', rdata:'ns0.mydomain.com.' },
 *  { name:'mydomain.com', ttl: 259200, rdtype:'NS', rdata:'ns1.mydomain.com.' },
 *  { name:'mydomain.com', ttl: 259200, rdtype:'MX', rdata:'10 mail.mydomain.com.' },
 *  { name:'w0.mydomain.com', ttl: 259200, rdtype:'A', rdata:'192.168.1.1' },
 *  { name:'w1.mydomain.com', ttl: 259200, rdtype:'A', rdata:'192.168.1.2' },
 *  { name:'mydomain.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.mydomain.com.' },
 *  { name:'mail.mydomain.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.mydomain.com.' },
 *  { name:'ns0.mydomain.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.mydomain.com.' },
 *  { name:'ns1.mydomain.com', ttl: 259200, rdtype:'CNAME', rdata:'w1.mydomain.com.' },
 *  { name:'www.mydomain.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.mydomain.com.' },
 *  { name:'ftp.mydomain.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.mydomain.com.' }
 * ]
 * 
 * db.test.com.insertMany([{name:'@', ttl: 259200, rdtype:'SOA', rdata:'test.com. www.test.com. 200309181 28800 7200 86400 28800'},{name:'@', ttl: 259200, rdtype:'NS', rdata:'ns0.test.com.'},{name:'@', ttl: 259200, rdtype:'NS', rdata:'ns1.test.com.'},{name:'@', ttl: 259200, rdtype:'MX', rdata:'10 mail.test.com.'},{name:'@', ttl: 259200, rdtype:'CNAME', rdata:'w0.test.com.'},{name:'w0.test.com', ttl: 259200, rdtype:'A', rdata:'192.168.1.1'},{name:'w1.test.com', ttl: 259200,rdtype:'A',rdata:'192.168.1.2'},{name:'mail.test.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.test.com.'},{name:'ns0.test.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.test.com.'},{name:'ns1.test.com', ttl: 259200, rdtype:'CNAME',rdata:'w1.test.com.'},{name:'www.test.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.test.com.'},{ name:'ftp.test.com', ttl: 259200, rdtype:'CNAME', rdata:'w0.test.com.'}])
 * 
 * Example entry in named.conf
 * ===========================
 * zone "mydomain.com" {
 *  type master;
 *  notify no;
 *  database "mongodb user:pass@127.0.0.1:27017/database 0";
 * };
 *
 * debug should be 1 (on) or 0 (off)
 */

/*
 * This provides the externally loadable MongoDB DLZ module, without
 * update support
 */

#include <dlz_minimal.h>
#include <dlz_mongodb.h>

#define ALLNODES 1
#define ALLOWXFR 2
#define AUTHORITY 3
#define FINDZONE 4
#define COUNTZONE 5
#define LOOKUP 6

/*%
 * Structure to hold everthing needed by this "instance" of the MongoDB
 * driver. The driver code is only loaded once, but may have
 * many separate instances.
 */
typedef struct {
	mongoc_client_pool_t *pool;
	char debug;

	/* Helper functions from the dlz_dlopen driver */
	log_t *log;
	dns_sdlz_putrr_t *putrr;
	dns_sdlz_putnamedrr_t *putnamedrr;
	dns_dlz_writeablezone_t *writeable_zone;
} mongodb_instance_t;

/* forward references */

isc_result_t dlz_findzonedb(void *dbdata, const char *name,
							dns_clientinfomethods_t *methods,
							dns_clientinfo_t *clientinfo);

void dlz_destroy(void *dbdata);
static void b9_add_helper(mongodb_instance_t *dbi, const char *helper_name, void *ptr);

/*
 * Private methods
 */

// Test database connection.
static isc_result_t db_connect_test(mongoc_uri_t *uri, void *dbdata) {
	isc_result_t result = ISC_R_SUCCESS;
	mongodb_instance_t *dbi = (mongodb_instance_t *)dbdata;
	mongoc_client_t *client = NULL;
	bson_t *command, *reply = NULL;
	bson_error_t error;
	int status = 0;

	if (dbi->debug)
		dbi->log(ISC_LOG_INFO, "Trying %s ...", mongoc_uri_get_string(uri));

	client = mongoc_client_new_from_uri(uri);
	if (!client) {
		dbi->log(ISC_LOG_ERROR, "Failed to parse MongoDB URI for database '%s'", mongoc_uri_get_database(uri));
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	command = BCON_NEW("connectionStatus", BCON_INT32(1), "showPrivileges", BCON_BOOL(0));
	status = mongoc_client_command_simple(client, "admin", command, NULL, reply, &error);

	if (!status) {
		dbi->log(ISC_LOG_ERROR, "%s", error.message);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	dbi->log(ISC_LOG_INFO, "'%s' connection test passed successfully.", mongoc_uri_get_database(uri));

cleanup:
	if (reply)
		bson_destroy(reply);
	if (command)
		bson_destroy(command);
	if (client)
		mongoc_client_destroy(client);

	return (result);
}

char * get_domain(const char *str) {
        int len = strlen(str);
        int count = 0;
        char *p = NULL;
        for (p = str+len; p > str; p--)
                if (*p == '.')
                        if (++count == 2)
                                return p+1;
        return str;
}

/*%
 * This function is the real core of the module. Zone, name
 * and client strings are passed in (or NULL is passed if the
 * string is not available). The type of query we want to run
 * is indicated by the query flag, and the dbdata object is passed
 * passed in to.
 * The function will construct and run the query, hopefully getting
 * a result set.
 */
static isc_result_t mongodb_get_results(const char *zone, const char *name,
										const char *client, unsigned int op,
										void *dbdata, void *ptr) {
	isc_result_t result = ISC_R_FAILURE;
	mongodb_instance_t *dbi = (mongodb_instance_t *)dbdata;
	bson_t *query = NULL;
	mongoc_client_t *mclient = NULL;
	mongoc_collection_t *collection = NULL;
	mongoc_cursor_t *cursor = NULL;
	const bson_t *document = NULL;
	const char * key = NULL, * rdata = NULL, * rdtype = NULL;
	uint32_t ttl = 0;
	bson_iter_t it;
	bson_error_t error;
	char *domain = get_domain(zone);

	if (dbi->debug)
		dbi->log(ISC_LOG_DEBUG(1), "mongodb_get_results args received : zone='%s', name='%s', client='%s', op='%d'", domain, name, client, op);

	/* Create query based on operation code */
	switch(op) {
		case ALLNODES:
			query = BCON_NEW("rdtype", "{", "$nin", "[", BCON_UTF8("SOA"), BCON_UTF8("NS"), "]", "}");
			break;
		case ALLOWXFR:
			query = BCON_NEW("xfr", BCON_INT32(1), "client", BCON_UTF8(client));
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		case AUTHORITY:
			query = BCON_NEW("name", BCON_UTF8(domain), "rdtype", "{", "$in", "[", BCON_UTF8("SOA"), BCON_UTF8("NS"), "]", "}");
			break;
		case FINDZONE:
			query = BCON_NEW("name", BCON_UTF8(domain), "rdtype", BCON_UTF8("SOA"));
			break;
		case COUNTZONE:
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		case LOOKUP:
			query = BCON_NEW("name", BCON_UTF8((strcmp(name, "@") == 0) ? zone : name), "rdtype", "{", "$nin", "[", BCON_UTF8("SOA"), BCON_UTF8("NS"), "]", "}");
			break;
		default:
			dbi->log(ISC_LOG_ERROR, "Incorrect operation flag passed to mongodb_get_results!");
			result = ISC_R_UNEXPECTED;
			goto cleanup;
	}

	if (!zone) {
		dbi->log(ISC_LOG_ERROR, "No zone passed to mongodb_get_results!");
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}

	mclient = mongoc_client_pool_try_pop(dbi->pool);
	if (!mclient) {
		dbi->log(ISC_LOG_ERROR, "mongodb_get_results : Failed to open a MongoDB connection!");
		goto cleanup;
	}

	const mongoc_uri_t *uri = mongoc_client_get_uri(mclient);
	if (dbi->debug)
		dbi->log(ISC_LOG_DEBUG(1), "mongodb_get_results : Database connection successful. Opening collection '%s' on '%s'...", zone, mongoc_uri_get_string(uri));

	collection = mongoc_client_get_collection(mclient, mongoc_uri_get_database(uri), domain);
	if (!collection) {
		dbi->log(ISC_LOG_ERROR, "mongodb_get_results : Failed to fetch collection '%s'!", zone);
		goto cleanup;
	}

	char *json = bson_as_json(query, NULL);
	dbi->log(ISC_LOG_DEBUG(1), "mongodb_get_results : Query ='%s'", json);
	free(json);
	cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
	if (!cursor) {
		dbi->log(ISC_LOG_ERROR, "mongodb_get_results : Query Failed!");
		goto cleanup;
	}

	while (mongoc_cursor_next(cursor, &document)) {
		if (mongoc_cursor_error(cursor, &error)) {
			dbi->log(ISC_LOG_ERROR, "mongodb_get_results : Cursor Failure! - '%s'", error.message);
			goto cleanup;
		}

		bson_iter_init(&it, document);
		while (bson_iter_next(&it)) {
			key = bson_iter_key(&it);
			if(strcmp(key, "ttl") == 0) {
				ttl = (uint32_t) bson_iter_double(&it);
			} else if(strcmp(key, "rdtype") == 0) {
				rdtype = bson_iter_utf8(&it, NULL);
			} else if(strcmp(key, "rdata") == 0) {
				rdata = bson_iter_utf8(&it, NULL);
			}
		}

		switch(op) {
			case ALLNODES:
				if (dbi->debug)
					dbi->log(ISC_LOG_DEBUG(1), "mongodb_get_results : putnamedrr name:'%s', type:'%s', ttl:'%d', rdata:'%s'", name, rdtype, ttl, rdata);
				result = dbi->putnamedrr((dns_sdlzallnodes_t *) ptr, name, rdtype, ttl, rdata);
				break;
			case ALLOWXFR:
				result = ISC_R_NOTIMPLEMENTED;
				break;
			case FINDZONE:
				result = (bson_count_keys(document) > 0) ? ISC_R_SUCCESS : ISC_R_NOTFOUND;
				break;
			case COUNTZONE:
				break;
			case AUTHORITY:
			case LOOKUP:
			default:
				if (dbi->debug)
					dbi->log(ISC_LOG_DEBUG(1), "mongodb_get_results : putrr type:'%s', ttl:'%d', rdata:'%s'", rdtype, ttl, rdata);
				result = dbi->putrr((dns_sdlzlookup_t *) ptr, rdtype, ttl, rdata);
		}

		if (result != ISC_R_SUCCESS) {
			dbi->log(ISC_LOG_ERROR, "mongodb_get_results : putnamedrr failed!");
			goto cleanup;
		}
	}

cleanup:
	if (query)
		bson_destroy(query);
	if (cursor)
		mongoc_cursor_destroy(cursor);
	if (collection)
		mongoc_collection_destroy(collection);
	if (mclient)
		mongoc_client_pool_push(dbi->pool, mclient);

	return (result);
}

/*
 * DLZ methods
 */

/*% Determine if the client is allowed to perform a zone transfer */
isc_result_t dlz_allowzonexfr(void *dbdata, const char *name, const char *client) {
	isc_result_t result;

	/* check to see if we are authoritative for the zone first */
	result = dlz_findzonedb(dbdata, name, NULL, NULL);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	/* get all the zone data */
	result = mongodb_get_results(name, NULL, client, ALLOWXFR, dbdata, NULL);
	return (result);
}

/*%
 * If the client is allowed to perform a zone transfer, the next order of
 * business is to get all the nodes in the zone, so bind can respond to the
 * query.
 */
isc_result_t dlz_allnodes(const char *zone, void *dbdata, dns_sdlzallnodes_t *allnodes) {
	return (mongodb_get_results(zone, NULL, NULL, ALLNODES, dbdata, allnodes));
}

/*%
 * If the lookup function does not return SOA or NS records for the zone,
 * use this function to get that information for named.
 */
isc_result_t dlz_authority(const char *zone, void *dbdata, dns_sdlzlookup_t *lookup) {
	return (mongodb_get_results(zone, NULL, NULL, AUTHORITY, dbdata, lookup));
}

/*% determine if the zone is supported by (in) the database */
isc_result_t dlz_findzonedb(void *dbdata, const char *name, dns_clientinfomethods_t *methods,
							dns_clientinfo_t *clientinfo) {
	UNUSED(methods);
	UNUSED(clientinfo);
	return (mongodb_get_results(name, NULL, NULL, FINDZONE, dbdata, NULL));
}

/*% If zone is supported, lookup up a (or multiple) record(s) in it */
isc_result_t dlz_lookup(const char *zone, const char *name,
						void *dbdata, dns_sdlzlookup_t *lookup,
						dns_clientinfomethods_t *methods,
						dns_clientinfo_t *clientinfo) {
	isc_result_t result;

	UNUSED(methods);
	UNUSED(clientinfo);

	result = mongodb_get_results(zone, name, NULL, LOOKUP, dbdata, lookup);

	return (result);
}

/*
 * Create an instance of the module:
 * Create a connection pool and save any necessary information in dbdata.
 *
 * argv[0] is path of this module's so file to be loaded by dlopen
 * argv[1] is the connection string
 * argv[2] (if present) is the debug switch
 */
isc_result_t dlz_create(const char *dlzname, unsigned int argc, char *argv[], void **dbdata, ...) {
	mongodb_instance_t *dbi = NULL;
	const char *helper_name;
	va_list ap;
	char buffer[2000];
	isc_result_t result = ISC_R_FAILURE;
	bson_error_t error;

	UNUSED(dlzname);

	/* allocate memory for MongoDB instance */
	dbi = calloc(1, sizeof(mongodb_instance_t));
	if (!dbi)
		return (ISC_R_NOMEMORY);
	memset(dbi, 0, sizeof(mongodb_instance_t));

	dbi->pool       = NULL;
	dbi->debug      = 0;

	/* Fill in the helper functions */
	va_start(ap, dbdata);
	while ((helper_name = va_arg(ap, const char*)) != NULL)
		b9_add_helper(dbi, helper_name, va_arg(ap, void*));
	va_end(ap);

	if (argc < 2 || argc > 3) {
		dbi->log(ISC_LOG_ERROR, "Wrong configuration. Config Template : dlz 'dlopen <path> <connection string, e.g. user:pass@host:port/db> [0|1]' (see https://docs.mongodb.com/manual/reference/connection-string)");
		goto cleanup;
	}

	snprintf(buffer, sizeof(buffer), "mongodb://%s", argv[1]);
	mongoc_uri_t *uri = mongoc_uri_new_with_error(buffer, &error);
	if (! uri) {
		dbi->log(ISC_LOG_ERROR, "Failed to create the URI : %s\n", error.message);
		goto cleanup;
	}

	if ((argc > 2) && (strcmp(argv[2],"1") == 0 || strcmp(argv[2],"true") == 0))
		dbi->debug = 1;

	mongoc_init();
	result = db_connect_test(uri, dbi);

	if (result != ISC_R_SUCCESS)
	    goto cleanup;

	dbi->pool = mongoc_client_pool_new(uri);
	mongoc_client_pool_set_appname(dbi->pool, "bind9");
	*dbdata = dbi;

cleanup:
	if (uri)
		mongoc_uri_destroy(uri);
	if (result != ISC_R_SUCCESS)
		dlz_destroy(dbi);
	return (result);
}

void dlz_destroy(void *dbdata) {
	if (dbdata) {
		mongodb_instance_t *dbi = (mongodb_instance_t *)dbdata;

		if (dbi->pool)
			mongoc_client_pool_destroy(dbi->pool);

		mongoc_cleanup();
		free(dbdata);
	}
}

/*
 * Return the version of the API
 */
int dlz_version(unsigned int *flags) {
	*flags |= DNS_SDLZFLAG_RELATIVERDATA;
	*flags |= DNS_SDLZFLAG_THREADSAFE;
	return (DLZ_DLOPEN_VERSION);
}

/*
 * Register a helper function from the bind9 dlz_dlopen driver
 */
static void b9_add_helper(mongodb_instance_t *dbi, const char *helper_name, void *ptr) {
	if (strcmp(helper_name, "log") == 0)
		dbi->log = (log_t *)ptr;
	if (strcmp(helper_name, "putrr") == 0)
		dbi->putrr = (dns_sdlz_putrr_t *)ptr;
	if (strcmp(helper_name, "putnamedrr") == 0)
		dbi->putnamedrr = (dns_sdlz_putnamedrr_t *)ptr;
	if (strcmp(helper_name, "writeable_zone") == 0)
		dbi->writeable_zone = (dns_dlz_writeablezone_t *)ptr;
}

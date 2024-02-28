/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <open62541/plugin/eventloop.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/types.h>

#include "server/ua_server_internal.h"
#include "server/ua_services.h"

#include "testing_clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "check.h"

typedef struct {
    UA_Server *server;
    UA_EventLoop *eventLoop;
    UA_DelayedCallback *deleteCallback;
} ELData;

static void
deleteServer(void *application, void *context) {
    ELData *data = (ELData *)application;
    UA_StatusCode status;
    status = UA_Server_delete(data->server);
    data->server = NULL;
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);
    data->eventLoop->stop(data->eventLoop);
}

static void
runShutdown(UA_Server *server, void *context) {
    // ELData *data = (ELData *)context;
    UA_StatusCode status;
    status = UA_Server_run_shutdown(server);
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);
}

static void
onServerLifecycle(UA_Server *server, UA_LifecycleState state) {
    if(state == UA_LIFECYCLESTATE_STOPPED) {
        // we may still be inside of UA_Server_run_shutdown here,
        // so better postpone the delete
        UA_ServerConfig *cfg = UA_Server_getConfig(server);
        ELData *data = (ELData *)cfg->context;
        data->eventLoop->addDelayedCallback(data->eventLoop, data->deleteCallback);
    }
}

START_TEST(checkServer_externalEventLoop) {
    UA_StatusCode status;
    ELData data;
    UA_EventLoop *el;
    UA_ServerConfig cfg;
    UA_ServerConfig *config;
    UA_ConnectionManager *cm;
    UA_DelayedCallback deleteCallback;
    UA_Server *server;

    server = UA_Server_new();
    ck_assert_ptr_ne(server, NULL);

    deleteCallback.next = NULL;
    deleteCallback.callback = deleteServer;
    deleteCallback.application = &data;
    deleteCallback.context = NULL;

    data.deleteCallback = &deleteCallback;

    memset(&cfg, 0, sizeof(cfg));
    config = &cfg;

    config->context = &data;

    el = UA_EventLoop_new_POSIX(NULL);
    ck_assert_ptr_ne(el, NULL);
    cm = UA_ConnectionManager_new_POSIX_TCP(UA_STRING((char *)"tcp connection manager"));
    ck_assert_ptr_ne(cm, NULL);

    data.eventLoop = el;

    status = el->registerEventSource(el, &cm->eventSource);
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);

    status = el->start(el);
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);

    config->eventLoop = el;
    config->externalEventLoop = true;

    status = UA_ServerConfig_setDefault(config);
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);

    config->notifyLifecycleState = onServerLifecycle;

    server = UA_Server_newWithConfig(config);
    ck_assert_ptr_ne(server, NULL);

    data.server = server;

    status = UA_Server_run_startup(server);
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);

    status = UA_Server_addTimedCallback(
        server, &runShutdown, NULL,
        el->dateTime_nowMonotonic(el) + (1000ull * UA_DATETIME_MSEC), NULL);
    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);

    while(el->state != UA_EVENTLOOPSTATE_STOPPED && status == UA_STATUSCODE_GOOD) {
        status = el->run(el, 100);
        UA_fakeSleep(100);
    }

    ck_assert_int_eq(status, UA_STATUSCODE_GOOD);
}
END_TEST

int
main(void) {
    Suite *suite = suite_create("server");

    TCase *tcase = tcase_create("server - eventloop");
    tcase_add_test(tcase, checkServer_externalEventLoop);
    suite_add_tcase(suite, tcase);

    SRunner *runner = srunner_create(suite);
    srunner_set_fork_status(runner, CK_NOFORK);
    srunner_run_all(runner, CK_NORMAL);
    int number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

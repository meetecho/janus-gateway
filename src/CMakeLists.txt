set(LIBRARY_NAME "janusgateway")

set(Header_Files
        apierror.h
        auth.h
        cmdline.h
        config.h
        debug.h
        dtls.h
        dtls-bio.h
        events.h
        ice.h
        janus.h
        log.h
        mutex.h
        record.h
        refcount.h
        rtcp.h
        rtp.h
        rtpsrtp.h
        sctp.h
        sdp.h
        sdp-utils.h
        ip-utils.h
        turnrest.h
        utils.h
        version.h
        text2pcap.h
        # TODO: Move these into their own separate targets, found through their own CMakeLists.txt
        ../plugins/plugin.h
        ../transports/transport.h
        ../events/eventhandler.h
        ../loggers/logger.h
        )
source_group("Header Files" FILES "${Header_Files}")

set(Source_Files
        apierror.c
        auth.c
        cmdline.c
        config.c
        dtls.c
        dtls-bio.c
        events.c
        ice.c
        janus.c
        log.c
        record.c
        rtcp.c
        rtp.c
        sctp.c
        sdp.c
        sdp-utils.c
        ip-utils.c
        turnrest.c
        utils.c
        version.c
        text2pcap.c
        # TODO: Move these into their own separate targets, found through their own CMakeLists.txt
        ../plugins/plugin.c
        ../transports/transport.c
        )
source_group("Source Files" FILES "${Source_Files}")

add_library("${LIBRARY_NAME}" "${Header_Files}" "${Source_Files}")


target_include_directories(
        "${LIBRARY_NAME}"
        INTERFACE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
        "$<INSTALL_INTERFACE:include>"
        #"${_pp_headers}"
)

target_link_libraries("${LIBRARY_NAME}" PUBLIC "${PROJECT_LOWER_NAME}_compiler_flags")

set_target_properties(
        "${LIBRARY_NAME}"
        PROPERTIES
        LINKER_LANGUAGE
        C
)

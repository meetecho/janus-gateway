cmake_minimum_required(VERSION 2.8.4)
project(janus_gateway)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    plugins/janus_audiobridge.c
    plugins/janus_echotest.c
    plugins/janus_recordplay.c
    plugins/janus_sip.c
    plugins/janus_streaming.c
    plugins/janus_videocall.c
    plugins/janus_videoroom.c
    plugins/janus_voicemail.c
    plugins/plugin.c
    plugins/plugin.h
    postprocessing/janus-pp-rec.c
    postprocessing/pp-opus.c
    postprocessing/pp-opus.h
    postprocessing/pp-rtp.h
    postprocessing/pp-webm.c
    postprocessing/pp-webm.h
    apierror.c
    apierror.h
    config.c
    config.h
    debug.h
    dtls.c
    dtls.h
    ice.c
    ice.h
    janus.c
    janus.h
    mutex.h
    record.c
    record.h
    rtcp.c
    rtcp.h
    rtp.h
    sctp.c
    sctp.h
    sdp.c
    sdp.h
    utils.c
    utils.h)

add_executable(janus_gateway ${SOURCE_FILES})
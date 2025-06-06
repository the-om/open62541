####################
# Nodeset Examples #
####################

###################
# Custom XML      #
###################

set(FILE_CSV_DIRPREFIX ${PROJECT_SOURCE_DIR}/nodeset)
set(FILE_BSD_DIRPREFIX ${PROJECT_SOURCE_DIR}/nodeset)
set(FILE_NS_DIRPREFIX ${PROJECT_SOURCE_DIR}/nodeset)

if(NOT CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # needed or cmake doesn't recognize dependencies of generated files
    get_target_property(OPEN62541_BIN_DIR open62541::open62541 BINARY_DIR)
    set(PROJECT_BINARY_DIR ${OPEN62541_BIN_DIR})
endif()

# generate namespace from XML file
ua_generate_nodeset_and_datatypes(NAME "example"
                                  FILE_NS "${FILE_NS_DIRPREFIX}/server_nodeset.xml")

# The .csv file can be created from within UaModeler or manually
ua_generate_nodeid_header(NAME "example_nodeids"
                          ID_PREFIX "EXAMPLE_NS"
                          TARGET_SUFFIX "ids_example"
                          FILE_CSV "${FILE_CSV_DIRPREFIX}/server_nodeset.csv")

add_example(server_nodeset server_nodeset.c
            ${UA_NODESET_EXAMPLE_SOURCES}
            ${PROJECT_BINARY_DIR}/src_generated/open62541/example_nodeids.h)
add_dependencies(server_nodeset open62541-generator-ns-example open62541-generator-ids_example)

if(UA_NAMESPACE_ZERO STREQUAL "FULL")
    ua_generate_nodeset_and_datatypes(
        NAME "testnodeset"
        FILE_CSV "${FILE_CSV_DIRPREFIX}/testnodeset.csv"
        FILE_BSD "${FILE_BSD_DIRPREFIX}/testtypes.bsd"
        FILE_NS "${FILE_NS_DIRPREFIX}/testnodeset.xml"
        INTERNAL
    )
    add_example(server_testnodeset server_testnodeset.c
                ${UA_NODESET_TESTNODESET_SOURCES}
                ${UA_TYPES_TESTNODESET_SOURCES})
    add_dependencies(server_testnodeset open62541-generator-ns-testnodeset)
endif()


###################
# PLCopen Nodeset #
###################

if(NOT CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(FILE_CSV_DIRPREFIX ${UA_NODESET_DIR})
    set(FILE_BSD_PLCOPEN_DIRPREFIX ${UA_NODESET_DIR})
    set(FILE_BSD_POWERLINK_DIRPREFIX ${PROJECT_SOURCE_DIR}/nodeset)
    set(FILE_NS_DIRPREFIX ${UA_NODESET_DIR})
else()
    set(FILE_CSV_DIRPREFIX ${UA_NODESET_DIR})
    set(FILE_BSD_PLCOPEN_DIRPREFIX ${UA_NODESET_DIR})
    set(FILE_BSD_POWERLINK_DIRPREFIX ${PROJECT_SOURCE_DIR}/nodeset)
    set(FILE_NS_DIRPREFIX ${UA_NODESET_DIR})
endif()

# PLCopen requires the full ns0 as basis
if(UA_NAMESPACE_ZERO STREQUAL "FULL")

    # Generate types and namespace for DI
    ua_generate_nodeset_and_datatypes(
        NAME "di"
        FILE_CSV "${FILE_CSV_DIRPREFIX}/DI/Opc.Ua.Di.NodeIds.csv"
        FILE_BSD "${FILE_BSD_PLCOPEN_DIRPREFIX}/DI/Opc.Ua.Di.Types.bsd"
        FILE_NS "${FILE_NS_DIRPREFIX}/DI/Opc.Ua.Di.NodeSet2.xml"
        INTERNAL
    )

    # generate PLCopen namespace which is using DI
    ua_generate_nodeset_and_datatypes(
        NAME "plc"
        # PLCopen does not define custom types. Only generate the nodeset
        FILE_NS "${FILE_NS_DIRPREFIX}/PLCopen/Opc.Ua.PLCopen.NodeSet2_V1.02.xml"
        # PLCopen depends on the di nodeset, which must be generated before
        DEPENDS "di"
        INTERNAL
    )

    add_example(server_nodeset_plcopen server_nodeset_plcopen.c
                ${UA_NODESET_DI_SOURCES}
                ${UA_NODESET_PLC_SOURCES}
                ${UA_TYPES_DI_SOURCES}
                ${UA_TYPES_PLC_SOURCES})
    add_dependencies(server_nodeset_plcopen open62541-generator-ns-plc)

    # POWERLINK requires the full ns0 as basis
    # generate powerlink namespace which is using DI
    ua_generate_nodeset_and_datatypes(
        NAME "powerlink"
        FILE_CSV "${FILE_CSV_DIRPREFIX}/POWERLINK/Opc.Ua.POWERLINK.NodeIds.csv"
        FILE_BSD "${FILE_BSD_POWERLINK_DIRPREFIX}/Opc.Ua.POWERLINK.NodeSet2.bsd"
        FILE_NS "${FILE_NS_DIRPREFIX}/POWERLINK/Opc.Ua.POWERLINK.NodeSet2.xml"
        # POWERLINK depends on the di nodeset, which must be generated before
        DEPENDS "di"
        INTERNAL
    )

    add_example(server_nodeset_powerlink server_nodeset_powerlink.c
                ${UA_NODESET_DI_SOURCES}
                ${UA_NODESET_POWERLINK_SOURCES}
                ${UA_TYPES_DI_SOURCES}
                ${UA_TYPES_POWERLINK_SOURCES})
    add_dependencies(server_nodeset_powerlink open62541-generator-ns-powerlink)
endif()

if(UA_ENABLE_NODESET_INJECTOR)
    set(UA_NODESETINJECTOR_SOURCE_FILES ${UA_NODESETINJECTOR_SOURCE_FILES} PARENT_SCOPE)
endif()

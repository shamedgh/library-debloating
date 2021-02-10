import sys
import os
import re

sys.path.insert(0, './python-utils/')

import util
import graph
import binaryAnalysis

class Piecewise:
    """
    This class can be used to perform debloating based on the piece-wise paper (they should've released and extendable code, but didn't)
    """
    def __init__(self, binaryPath, binaryCfgPath, libcCfgPath, cfgPath, logger, cfginputseparator=":"):
        self.binaryPath = binaryPath
        self.binaryCfgPath = binaryCfgPath
        self.libcCfgPath = libcCfgPath
        self.cfgPath = cfgPath
        self.libcSeparator = cfginputseparator
        self.logger = logger

    def cleanLib(self, libName):
        self.logger.debug("cleanLib libName input: %s", libName)
        if ( ".so" in libName ):
            libName = re.sub("-.*so",".so",libName)
            libName = libName[:libName.index(".so")]
            #libName = libName + ".so"
        self.logger.debug("cleanLib libName output: %s", libName)
        return libName

    def createCompleteGraph(self, exceptList=list()):
        '''TODO
        1. Extract required libraries from binary (ldd)
        2. Find call graph for each library from specified folder (input: callgraph folder)
        3. Create start->leaves graph from complete call graph
        4. Create complete global graph for application along with all libraries
            Complete graph:
                Application: entire graph
                Libc: entire graph
                Other Libraries: start->leave partition
        '''
        libcRelatedList = ["ld", "libc", "libdl", "libcrypt", "libnss_compat", "libnsl", "libnss_files", "libnss_nis", "libpthread", "libm", "libresolv", "librt", "libutil", "libnss_dns"]
        libraryCfgGraphs = dict()
        librarySyscalls = set()  #Only for libraries which we DO NOT have the CFG
        libraryToPathDict = util.readLibrariesWithLdd(self.binaryPath)

        startNodeToLibDict = dict()

        libcGraph = graph.Graph(self.logger)
        libcGraph.createGraphFromInput(self.libcCfgPath, self.libcSeparator)

        completeGraph = graph.Graph(self.logger)
        result = completeGraph.createGraphFromInput(self.binaryCfgPath)
        if ( result == -1 ):
            self.logger.error("Failed to create graph for input: %s", self.binaryCfgPath)
            sys.exit(-1)
        
        for libraryName, libPath in libraryToPathDict.items():
            self.logger.info("Checking library: %s", libraryName)
            libraryCfgFileName = self.cleanLib(libraryName) + ".callgraph.out"
            libraryCfgFilePath = self.cfgPath + "/" + libraryCfgFileName
            if ( libraryName not in libcRelatedList and libraryName not in exceptList ):
                if ( os.path.isfile(libraryCfgFilePath) ):
                    #We have the CFG for this library
                    self.logger.info("The library call graph exists for: %s", libraryName)

                    libraryGraph = graph.Graph(self.logger)
                    libraryGraph.createGraphFromInput(libraryCfgFilePath)
                    self.logger.info("Finished create graph object for library: %s", libraryName)
                    libraryStartNodes = libraryGraph.extractStartingNodes()
                    self.logger.info("Finished extracting start nodes for library: %s", libraryName)

                    #We're going keep a copy of the full library call graph, for later stats creation
                    libraryCfgGraphs[libraryName] = libraryGraph

                    #(Step 3 in todo list): We're going to make a smaller graph containing only start nodes and end nodes
                    #libraryStartToEndGraph = graph.Graph(self.logger)

                    for startNode in libraryStartNodes:
                        if ( startNodeToLibDict.get(startNode, None) ):
                            self.logger.warning("library startNode seen in more than one library: %s and %s", libraryName, startNodeToLibDict[startNode])
                        startNodeToLibDict[startNode] = libraryName
                        leaves = libraryGraph.getLeavesFromStartNode(startNode, list(), list())
                        for leaf in leaves:
                            #self.logger.debug("Adding edge %s->%s from library: %s to complete graph.", startNode, leaf, libraryName)
                            #libraryStartToEndGraph.addEdge(startNode, leaf)
                            completeGraph.addEdge(startNode, leaf)
                    #libraryGraphs[libraryName] = libraryStartToEndGraph
                elif ( os.path.isfile(libPath) ):
                    #We don't have the CFG for this library, all exported functions will be considered as starting nodes in our final graph
                    self.logger.info("The library call graph doesn't exist, considering all imported functions for: %s", libraryName)
                    libraryProfiler = binaryAnalysis.BinaryAnalysis(libPath, self.logger)
                    directSyscallSet, successCount, failedCount  = libraryProfiler.extractDirectSyscalls()
                    indirectSyscallSet = libraryProfiler.extractIndirectSyscalls(libcGraph)

                    librarySyscalls.update(directSyscallSet)
                    librarySyscalls.update(indirectSyscallSet)
                else:
                    self.logger.warning("Skipping library: %s because path: %s doesn't exist", libraryName, libPath)
            else:
                self.logger.info("Skipping except list library: %s", libraryName)

        return completeGraph, librarySyscalls, libraryCfgGraphs, libcGraph

    def extractAccessibleSystemCalls(self, startNodes, exceptList=list()):
        completeGraph, librarySyscalls, libraryCfgGraphs, libcGraph = self.createCompleteGraph(exceptList)

        accessibleFuncs = set()
        allVisitedNodes = set()
        accessibleSyscalls = set()
        for startNode in startNodes:
            self.logger.debug("Iterating startNode: %s", startNode)
            accessibleFuncs.update(completeGraph.getLeavesFromStartNode(startNode, list(), list()))

        for accessibleFunc in accessibleFuncs:
            self.logger.debug("Iterating accessible function: %s", accessibleFunc)
            currentSyscalls, currentVisitedNodes = libcGraph.getSyscallFromStartNodeWithVisitedNodes(accessibleFunc)
            accessibleSyscalls.update(currentSyscalls)
            allVisitedNodes.update(currentVisitedNodes)

        self.logger.info("Accessible system calls after library specialization: %d, %s", len(accessibleSyscalls), str(accessibleSyscalls))
        self.logger.info("len(librarySyscalls): %d", len(librarySyscalls))
        accessibleSyscalls.update(librarySyscalls)
        self.logger.info("Accessible system calls after adding libraries without cfg: %d, %s", len(accessibleSyscalls), str(accessibleSyscalls))
        return accessibleSyscalls

    def extractAccessibleSystemCallsFromIndirectFunctions(self, directCfg, separator, exceptList=list()):
        indirectFunctionToSyscallMap = dict()

        tempGraph = graph.Graph(self.logger)
        result = tempGraph.createGraphFromInput(self.binaryCfgPath)
        indirectFunctions = tempGraph.extractIndirectOnlyFunctions(directCfg, separator)
        completeGraph, librarySyscalls, libraryCfgGraphs, libcGraph = self.createCompleteGraph(exceptList)

        for startNode in indirectFunctions:
            accessibleFuncs = set()
            allVisitedNodes = set()
            accessibleSyscalls = set()
            self.logger.debug("Iterating indirect-only function: %s", startNode)
            accessibleFuncs.update(completeGraph.getLeavesFromStartNode(startNode, list(), list(indirectFunctions)))

            for accessibleFunc in accessibleFuncs:
                self.logger.debug("Iterating accessible function: %s", accessibleFunc)
                currentSyscalls, currentVisitedNodes = libcGraph.getSyscallFromStartNodeWithVisitedNodes(accessibleFunc)
                accessibleSyscalls.update(currentSyscalls)
                allVisitedNodes.update(currentVisitedNodes)
            indirectFunctionToSyscallMap[startNode] = accessibleSyscalls
        return indirectFunctionToSyscallMap

    # This function can used instead of createCompleteGraph when we don't have access or do not require the 
    # callgraph of the binary itself (all the code in the binary is required)
    # Any imported function in the binary will be used as the starting points of this complete graph
    # The graph in this case will only consist of the libraries
    # TODO (02/2021): We have a bug here, we shouldn't check libraries with callgraphs and without in the same loop
    # We should either first create the complete graph for all libraries with a callgraph and then perform 
    # another loop for the libraries without a callgraph, or extract the start node from all libraries without 
    # a callgraph and then consider those start nodes for the complete graph
    # This bug also applies to the original createCompleteGraph
    def createCompleteGraphWithoutBinary(self, exceptList=list(), altLibPath=None, procLibraryDict=dict()):
        '''TODO
        1. Extract required libraries from binary (ldd)
        2. Find call graph for each library from specified folder (input: callgraph folder)
        3. Create start->leaves graph from complete call graph
        4. Create complete global graph for application along with all libraries
            Complete graph:
                Application: entire graph
                Libc: entire graph
                Other Libraries: start->leave partition
        '''
        libcRelatedList = ["ld", "libc", "libdl", "libcrypt", "libnss_compat", "libnsl", "libnss_files", "libnss_nis", "libpthread", "libm", "libresolv", "librt", "libutil", "libnss_dns"]
        libraryCfgGraphs = dict()
        librarySyscalls = set()  #Only for libraries which we DO NOT have the CFG
        if ( procLibraryDict and len(procLibraryDict) != 0 ):
            libraryToPathDict = procLibraryDict
            self.logger.debug("library debloating createCompleteGraphWithoutBinary library name and path received, no need for ldd")
        else:
            libraryToPathDict = util.readLibrariesWithLdd(self.binaryPath)

        startNodeToLibDict = dict()

        libcGraph = graph.Graph(self.logger)
        libcGraph.createGraphFromInput(self.libcCfgPath, self.libcSeparator)

        completeGraph = graph.Graph(self.logger)
        result = completeGraph.createGraphFromInput(self.libcCfgPath, self.libcSeparator)

        if ( result == -1 ):
            self.logger.error("Failed to create graph for input: %s", self.libcCfgPath)
            sys.exit(-1)

        libWithCallgraphSet = set()
        # Fixing bug: should create callgraph first, then extract start nodes and find accessible system calls        
        for libraryName, libPath in libraryToPathDict.items():
            if ( ".so" in libPath ):
                self.logger.info("Checking library: %s", libraryName)
                if libPath == "not found":
                    libraryFullName = altBinaryPath.strip().split("/")[-1]
                else:
                    libraryFullName = libPath.strip().split("/")[-1]
                libraryCfgVersionedFileName = libraryFullName + ".callgraph.out"
                libraryCfgVersionedFilePath = self.cfgPath + "/" + libraryCfgVersionedFileName
                libraryCfgFileName = self.cleanLib(libraryName) + ".callgraph.out"
                libraryCfgFilePath = self.cfgPath + "/" + libraryCfgFileName
                libraryName = self.cleanLib(libraryName)
                if ( libraryName not in libcRelatedList and libraryName not in exceptList ):
                    #altBinaryPath = self.existsInAltPath(libraryName, altLibPath)  #Using the cleaned version causes problem for libapr
                    altBinaryPath = self.existsInAltPath(libraryFullName, altLibPath)
                    if ( os.path.isfile(libraryCfgFilePath) ):

                        if ( os.path.isfile(libraryCfgVersionedFilePath) ):
                            libraryCfgFilePath = libraryCfgVersionedFilePath
                        else:
                            self.logger.warning("The library callgraph exists, but the version does not match: %s", libraryCfgVersionedFileName)
                        #We have the CFG for this library
                        libWithCallgraphSet.add(libraryName)
                        self.logger.info("The library call graph exists for: %s", libraryName)

                        libraryGraph = graph.Graph(self.logger)
                        libraryGraph.createGraphFromInput(libraryCfgFilePath)
                        self.logger.info("Finished create graph object for library: %s", libraryName)
                        libraryStartNodes = libraryGraph.extractStartingNodes()
                        self.logger.info("Finished extracting start nodes for library: %s", libraryName)

                        #We're going keep a copy of the full library call graph, for later stats creation
                        libraryCfgGraphs[libraryName] = libraryGraph

                        #(Step 3 in todo list): We're going to make a smaller graph containing only start nodes and end nodes
                        #libraryStartToEndGraph = graph.Graph(self.logger)

                        for startNode in libraryStartNodes:
                            if ( startNodeToLibDict.get(startNode, None) ):
                                self.logger.warning("library startNode seen in more than one library: %s and %s", libraryName, startNodeToLibDict[startNode])
                            startNodeToLibDict[startNode] = libraryName
                            leaves = libraryGraph.getLeavesFromStartNode(startNode, list(), list())
                            for leaf in leaves:
                                #self.logger.debug("Adding edge %s->%s from library: %s to complete graph.", startNode, leaf, libraryName)
                                #libraryStartToEndGraph.addEdge(startNode, leaf)
                                completeGraph.addEdge(startNode, leaf)
                        #libraryGraphs[libraryName] = libraryStartToEndGraph
                    else:
                        self.logger.warning("Skipping library: %s because down't have callgraph: %s", libraryName, libraryCfgFilePath)
                else:
                    self.logger.info("Skipping except list library: %s", libraryName)
            else:
                self.logger.info("Skipping non-library: %s in binary dependencies (can happen because of /proc", libraryName)

        for libraryName, libPath in libraryToPathDict.items():
            if ( ".so" in libPath ):
                self.logger.info("Checking library: %s", libraryName)
                libraryFullName = libraryName
                libraryCfgFileName = self.cleanLib(libraryName) + ".callgraph.out"
                libraryCfgFilePath = self.cfgPath + "/" + libraryCfgFileName
                libraryName = self.cleanLib(libraryName)
                if ( libraryName not in libWithCallgraphSet and libraryName not in libcRelatedList and libraryName not in exceptList ):
                    #altBinaryPath = self.existsInAltPath(libraryName, altLibPath)  #Using the cleaned version causes problem for libapr
                    altBinaryPath = self.existsInAltPath(libraryFullName, altLibPath)
                    if ( os.path.isfile(libPath) or altBinaryPath ):
                        #We don't have the CFG for this library, all exported functions will be considered as starting nodes in our final graph
                        self.logger.info("The library call graph doesn't exist, considering all imported functions for: %s", libraryName)
                        path = libPath if os.path.isfile(libPath) else altBinaryPath
                        self.logger.info("path: %s", path)
                        libraryProfiler = binaryAnalysis.BinaryAnalysis(path, self.logger)
                        directSyscallSet, successCount, failedCount  = libraryProfiler.extractDirectSyscalls()
                        indirectSyscallSet = libraryProfiler.extractIndirectSyscalls(completeGraph)

                        librarySyscalls.update(directSyscallSet)
                        librarySyscalls.update(indirectSyscallSet)
                    else:
                        self.logger.warning("Skipping library: %s because path: %s doesn't exist", libraryName, libPath)
                else:
                    self.logger.info("Skipping except list library: %s", libraryName)
            else:
                self.logger.info("Skipping non-library: %s in binary dependencies (can happen because of /proc", libraryName)

        return completeGraph, librarySyscalls, libraryCfgGraphs

    def extractAccessibleSystemCallsFromBinary(self, startNodes, exceptList=list(), altLibPath=None, procLibraryDict=dict()):
        self.logger.info("Extracting acessible system calls from binary")
        completeGraph, librarySyscalls, libraryCfgGraphs = self.createCompleteGraphWithoutBinary(exceptList, altLibPath, procLibraryDict)

        accessibleSyscalls = set()
        for startNode in startNodes:
            self.logger.debug("Iterating startNode: %s", startNode)
            currentSyscalls = completeGraph.getSyscallFromStartNode(startNode)
            accessibleSyscalls.update(currentSyscalls)

        self.logger.info("Accessible system calls after library specialization: %d, %s", len(accessibleSyscalls), str(accessibleSyscalls))
        self.logger.info("len(librarySyscalls): %d", len(librarySyscalls))
        accessibleSyscalls.update(librarySyscalls)
        self.logger.info("Accessible system calls after adding libraries without cfg: %d, %s", len(accessibleSyscalls), str(accessibleSyscalls))
        return accessibleSyscalls
        
    # checks if the library exists in the specified alternate path
    def existsInAltPath(self, libraryName, altLibPath):
        if altLibPath is None:
            return None
        self.logger.debug("existsInAltPath looking for: %s", libraryName)

        contents = os.listdir(altLibPath)

        for c in contents:
            if c.find(libraryName) != -1:
                self.logger.debug("existsInAltPath returning: %s", (os.path.abspath(altLibPath) + "/" + c))
                return os.path.abspath(altLibPath) + "/" + c

        return None

    # def getAltBinaryPath(self, libraryName, altLibPath):
    #     library = ""

    #     contents = os.listdir(altLibPath)

    #     for c in contents:
    #         if c.find(libraryName) != -1:
    #             return True

    #     return os.path.abspath(altLibPath) + "/" + libraryName

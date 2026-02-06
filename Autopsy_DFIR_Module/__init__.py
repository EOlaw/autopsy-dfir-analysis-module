# -*- coding: utf-8 -*-
# Autopsy DFIR Ingest Module
# Compatible with Autopsy Python (Jython 2.7)

from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from ForensicAnalysisModule import DFIRIngestModule

class DFIRModuleFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return "DFIR Analysis Module"

    def getModuleDescription(self):
        return "Performs file system, deleted file, timeline, keyword, and web artifact analysis."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return DFIRIngestModule()

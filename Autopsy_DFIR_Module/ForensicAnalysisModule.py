# -*- coding: utf-8 -*-
# Autopsy DFIR Ingest Module
# Compatible with Autopsy Python (Jython 2.7)

from org.sleuthkit.autopsy.ingest import (
    DataSourceIngestModule,
    IngestModuleFactoryAdapter,
    IngestMessage,
    IngestServices
)
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import (
    BlackboardArtifact,
    BlackboardAttribute,
    TskData
)
from java.util import UUID

class DFIRIngestModule(DataSourceIngestModule):

    def startUp(self, context):
        self.context = context

    def process(self, dataSource, progressBar):

        case = Case.getCurrentCase()
        fileManager = case.getServices().getFileManager()
        blackboard = case.getSleuthkitCase()

        files = fileManager.findFiles(dataSource, "%")

        for file in files:

            # Skip non-file system objects
            if file.getType() != TskData.TSK_DB_FILES_TYPE_ENUM.FS:
                continue

            fileName = file.getName().lower()

            # 1️⃣ Deleted File Detection
            if file.getMetaFlags() == TskData.TSK_FS_META_FLAG_ENUM.UNALLOC:
                artifact = file.newArtifact(
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT
                )
                artifact.addAttribute(
                    BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,
                        "DFIR Module",
                        "Deleted file detected"
                    )
                )

            # 2️⃣ Keyword Detection
            keywords = ["password", "confidential", "ssn", "private"]
            for word in keywords:
                if word in fileName:
                    artifact = file.newArtifact(
                        BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT
                    )
                    artifact.addAttribute(
                        BlackboardAttribute(
                            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD,
                            "DFIR Module",
                            word
                        )
                    )

            # 3️⃣ Executable Detection (File System Analysis)
            if fileName.endswith(".exe"):
                artifact = file.newArtifact(
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT
                )
                artifact.addAttribute(
                    BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,
                        "DFIR Module",
                        "Executable file discovered"
                    )
                )

            # 4️⃣ Timeline Artifact
            if file.getCrtime() > 0:
                artifact = file.newArtifact(
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_FILE_ACTIVITY
                )
                artifact.addAttribute(
                    BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED,
                        "DFIR Module",
                        file.getCrtime()
                    )
                )

        # Notify Autopsy UI
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.INFO,
            "DFIR Analysis Module",
            "DFIR analysis completed successfully."
        )
        IngestServices.getInstance().postMessage(message)

        return DataSourceIngestModule.ProcessResult.OK

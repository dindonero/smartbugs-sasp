from sarif_om import *

from smartbugs.src.output_parser.SarifHolder import isNotDuplicateRule, isNotDuplicateArtifact, parseLogicalLocation, \
    parseRule, \
    parseResult, parseArtifact, isNotDuplicateLogicalLocation


class Mythril:

    def parseSarif(self, mythril_output_results, file_path_in_repo):
        artifactsList = []
        resultsList = []
        logicalLocationsList = []
        rulesList = []

        for issue in mythril_output_results["analysis"]["issues"]:
            rule = parseRule(tool="mythril", vulnerability=issue["title"], full_description=issue["description"])
            result = parseResult(tool="mythril", vulnerability=issue["title"], level=issue["type"], uri=file_path_in_repo,
                                 line=issue["lineno"], snippet=issue["code"] if "code" in issue.keys() else None,
                                 logicalLocation=parseLogicalLocation(issue["function"],
                                                                      kind="function"))

            logicalLocation = parseLogicalLocation(name=issue["function"], kind="function")
            if isNotDuplicateLogicalLocation(logicalLocation, logicalLocationsList):
                logicalLocationsList.append(logicalLocation)
            resultsList.append(result)

            artifact = parseArtifact(uri=file_path_in_repo)

            if isNotDuplicateRule(rule, rulesList):
                rulesList.append(rule)

            if isNotDuplicateArtifact(artifact, artifactsList):
                artifactsList.append(artifact)

        tool = Tool(driver=ToolComponent(name="Mythril", version="0.4.25", rules=rulesList,
                                         information_uri="https://mythx.io/",
                                         full_description=MultiformatMessageString(
                                             text="Mythril analyses EVM bytecode using symbolic analysis, taint analysis and control flow checking to detect a variety of security vulnerabilities.")))

        run = Run(tool=tool, artifacts=artifactsList, logical_locations=logicalLocationsList, results=resultsList)

        return run

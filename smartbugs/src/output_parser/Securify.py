import numpy
from sarif_om import *

from smartbugs.src.output_parser.SarifHolder import isNotDuplicateArtifact, parseLogicalLocation, \
    parseArtifact, \
    parseRule, parseResult


class Securify:

    def parseSarif(self, securify_output_results, file_path_in_repo):
        artifactsList = []
        resultsList = []
        logicalLocationsList = []
        rulesList = []

        for name, analysis in securify_output_results["analysis"].items():
            contractName = name.split(':')[1]
            logicalLocationsList.append(parseLogicalLocation(name=contractName))
            artifact = parseArtifact(uri=file_path_in_repo)
            if isNotDuplicateArtifact(artifact, artifactsList):
                artifactsList.append(artifact)
            for vuln, analysisResult in analysis["results"].items():
                rule = parseRule(tool="securify", vulnerability=vuln)
                # Extra loop to add unique rule to tool in sarif
                for level, lines in analysisResult.items():
                    if len(lines) > 0:
                        rulesList.append(rule)
                        break
                for level, lines in analysisResult.items():
                    for lineNumber in lines:
                        result = parseResult(tool="securify", vulnerability=vuln, level=level, uri=file_path_in_repo,
                                             line=lineNumber)

                        resultsList.append(result)

        tool = Tool(driver=ToolComponent(name="Securify", version="0.4.25", rules=rulesList,
                                         information_uri="https://github.com/eth-sri/securify2",
                                         full_description=MultiformatMessageString(
                                             text="Securify uses formal verification, also relying on static analysis checks. Securify’s analysis consists of two steps. First, it symbolically analyzes the contract’s dependency graph to extract precise semantic information from the code. Then, it checks compliance and violation patterns that capture sufficient conditions for proving if a property holds or not.")))

        run = Run(tool=tool, artifacts=artifactsList, logical_locations=logicalLocationsList, results=resultsList)

        return run

    def parseSarifFromLiveJson(self, securify_output_results, file_path_in_repo):
        artifactsList = []
        resultsList = []
        rulesList = []

        for name, analysis in securify_output_results["analysis"].items():
            artifactsList.append(parseArtifact(uri=file_path_in_repo))
            for vuln, analysisResult in analysis["results"].items():
                rule = parseRule(tool="securify", vulnerability=vuln)
                # Extra loop to add unique rule to tool in sarif
                for level, lines in analysisResult.items():
                    if not isinstance(lines, list):
                        continue
                    if len(lines) > 0:
                        rulesList.append(rule)
                        break
                for level, lines in analysisResult.items():
                    if not isinstance(lines, list):
                        continue
                    for lineNumber in list(numpy.unique(lines)):
                        result = parseResult(tool="securify", vulnerability=vuln, level=level, uri=file_path_in_repo,
                                             line=int(lineNumber))  # without int() lineNumber returns null??!

                        resultsList.append(result)

        tool = Tool(driver=ToolComponent(name="Securify", version="0.4.25", rules=rulesList,
                                         information_uri="https://github.com/eth-sri/securify2",
                                         full_description=MultiformatMessageString(
                                             text="Securify uses formal verification, also relying on static analysis checks. Securify’s analysis consists of two steps. First, it symbolically analyzes the contract’s dependency graph to extract precise semantic information from the code. Then, it checks compliance and violation patterns that capture sufficient conditions for proving if a property holds or not.")))

        run = Run(tool=tool, artifacts=artifactsList, results=resultsList)

        return run

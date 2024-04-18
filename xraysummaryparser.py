import json
import urllib.parse


def fileName(path):
    p = path.split('/')
    return p[len(p)-1]


def dump_obj_panel(title, obj):
    print("<details><summary>{:s}</summary>".format(title))
    print("")
    print("```json")
    print(json.dumps(self.issue, indent=2))
    print("```")
    print("")
    print("</details>")
    print("")

def bail_with_data(m, d):
    print("###: :question: No xray data ({:s}) found for build {:s}/{:s}".format(m, self.buildName, self.buildNumber))
    dump_obj_panel("Response", d)
    exit(0)

class Issue:
    def __init__(self):
        self.severity = None
        self.summary = None
        self.cve = []
        self.impactedPaths = []
        self.issue = None
        self.buildName = None
        self.buildNumber = None
        self.issueTemplate = None
    
    def sortString(self):
        if len(self.impactedPaths) > 0:
            return fileName(self.impactedPaths[0])
        return ""

    def getPath(self):
        path = ""
        if len(self.impactedPaths) > 0:
            path = fileName(self.impactedPaths[0])
        return path

    def print(self):
        path = self.getPath()
        icon = ":fire:"
        if (self.severity == 'Critical'):
            icon = ":skull:"
        
        print("### {:s} {:s}  {:s}".format(icon, ", ".join(self.cve) , path))

        print(self.summary)
        print("")
        for p in self.impactedPaths:
            print("- `{:s}` _{:s}_".format(fileName(p),p[-100:]))
        print("<details><summary>Issue Details</summary>")
        print("")
        print("```json")
        print(json.dumps(self.issue, indent=2))
        print("```")
        print("")
        print("</details>")
        print("")
        print("<details><summary>Exception Request</summary>")

        possibleReason = "while {:s} is included in this build.  No process is actively using this library.  Further, this application is not customer-facing, it is not exposed to the internet, and intended only for internal LN use.".format(path)

        print("")
        print("[Create a new JFrog Exception Request Issue]({:s})".format(url))
        print("")
        print("| field | value |")
        print("| - | ---- |")
        print("| Build Name | `{:s}` |".format(self.buildName))
        print("| Build Version | `{:s}` |".format(self.buildNumber))        
        print("| Violation Id  | `{:s}` |".format(", ".join(self.cve)))
        print("| Possible Justification | `{:s}` |".format(possibleReason))
        print("")
        print("</details>")
        print("")

class XrayPrettifier:

    def set_build_name(self, buildName):
        self.buildName = buildName
    def set_build_number(self, buildNumber):
        self.buildNumber = buildNumber
    def set_fail_build(self, failBuild):
        self.failBuild = failBuild
    def set_issue_template(self, issueTemplate):
        self.issueTemplate = issueTemplate

    def __init__(self):
        self.hasData = False
        self.failBuild = False
        self.buildName = None
        self.buildNumber = None
        self.issueTemplate = None
   

    def analyze_results(self, filename):
        with open(filename) as f:
          data = json.load(f)
        
        hasData = False
        crit=[]
        high=[]
        message = None
        link = None

        if 'summary' not in data:
            return
        
        buildInfo = data['summary']
        if 'message' not in buildInfo:
            bail_with_data("missing summary.message", data)
        
        message = buildInfo['message']
        
        if 'more_details_url' not in buildInfo:
            bail_with_data("missing summary.more_details_url", data)
        
        link = buildInfo['more_details_url']
        hasData = True

        for alert in data['alerts']:
          for issue in alert['issues']:
            if 'severity' not in issue:
                continue
            issueObj = Issue()
            issueObj.buildName = self.buildName
            issueObj.buildNumber = self.buildNumber
            issueObj.severity = issue['severity']
            issueObj.summary = issue['summary']
            issueObj.template = self.issueTemplate
            issueObj.issue = issue
            if 'cve' not in issue:
                continue
            issueObj.cve.append(issue['cve'])
            for art in issue['impacted_artifacts']:
                for files in art['infected_files']:
                    issueObj.impactedPaths.append("{:s}/{:s}".format(art['path'], files['name']))
            if issue['severity'] == 'Critical':
                crit.append(issueObj)
            else:
                high.append(issueObj)
        crit.sort(key=lambda x: x.sortString())
        high.sort(key=lambda x: x.sortString())

        hasError = hasData and (len(crit) > 0 or len(high) > 0)

        if not hasData:
            bail_with_data("missing xray data", data)
        if len(crit) == 0 and len(high) == 0:
            print("## :trophy: 0 critical, 0 high xray vulernabilities for this build - [{:s}]({:s})".format(message, link))
            dump_obj_panel("response", data)
            exit(0)
        if len(crit) > 0:
            print("## :skull: {:d} critical, {:d} high xray vulnerabilities for this build - [{:s}]({:s})".format(len(crit) , len(high),message, link))
            dump_obj_panel("response", data)
        else:
            print("## :fire: {:d} critical, {:d} high xray vulnerabilities for this build - [{:s}]({:s})".format(len(crit) , len(high),message, link))
            dump_obj_panel("response", data)


        for c in crit:
            c.print()
        for h in high:
            h.print()

        if self.failBuild:
            exit(1)
        else:
            print("## :warning: XRAY Vulnerabilities found, but build will not be failed")
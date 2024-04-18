import json
import requests as request
import urllib.parse


def fileName(path):
    p = path.split('/')
    return p[len(p)-1]


def dump_obj_panel(title, obj):
    dump_strjson_panel(title, json.dumps(obj, indent=2))

def dump_strjson_panel(title, obj):
    print("<details><summary>{:s}</summary>".format(title))
    print("")
    print("```json")
    print(obj)
    print("```")
    print("")
    print("</details>")
    print("")

def bail_with_data(m, d):
    print("###: :question: No xray data ({:s}) found for build {:s}/{:s}".format(m, self.buildName, self.buildNumber))
    dump_obj_panel("Response", d)
    exit(0)


class MessageCard():
    def __init__(self, title, themeColor="000000"):
        self.title = title
        self.themeColor = themeColor
        self.sections = []

class MessageCardEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, MessageCard):
            return { 
                "title": o.title,
                "summary": o.title,
                "themeColor": o.themeColor,
                "sections": o.sections,
                "@context": "http://schema.org/extensions",
                "@type": "MessageCard"
            }
        else:
            return vars(o)

class Section:
    def __init__(self):
        self.activityTitle = ""
        self.activitySubtitle = ""
        self.markdown = True
        self.facts = []

class Fact:
    def __init__(self):
        self.name = ""
        self.value = ""

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

    def getIcon(self, as_emoji=False):
        icon = ":fire:"
        if as_emoji:
            icon = "🔥"
        if (self.severity == 'Critical'):
            icon = ":skull:"
            if as_emoji:
                icon = "💀"
        return icon

    def getCVE(self):
        return ", ".join(self.cve)

    def sanitizedSummary(self):
        if len(self.summary) > 512:
            return self.summary[:512]
        return self.summary

    def asSection(self):
        path = self.getPath()
        section = Section()
        section.activityTitle = "{:s} {:s}  {:s}".format(self.getIcon(as_emoji=True), self.getCVE(), path)
        section.activitySubtitle = self.sanitizedSummary()
        for p in self.impactedPaths:
            fact = Fact()
            fact.name = "{:s}".format(fileName(p))
            fact.value = "_{:s}_".format(p[-100:])
            section.facts.append(fact)
        return section

    def print(self):
        path = self.getPath()
        icon = self.getIcon()
        
        print("### {:s} {:s}  {:s}".format(icon, self.getCVE() , path))

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


        if (self.issueTemplate is None):
            return
        
        possibleReason = "while {:s} is included in this build.  No process is actively using this library.  Further, this application is not customer-facing, it is not exposed to the internet, and intended only for internal LN use.".format(path)
        possibleReason = urllib.parse.quote_plus(possibleReason)
        url = self.issueTemplate.format( build_name=self.buildName, build_version=self.buildNumber, build_number=self.buildNumber, violation_id=", ".join(self.cve), cve_id=", ".join(self.cve), possible_reason=possibleReason)
        print("<details><summary>Exception Request</summary>")
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
        if issueTemplate is None:
            self.issueTemplate = None
            return
        if issueTemplate == "":
            self.issueTemplate = None
            return
        if issueTemplate == "NA":
            self.issueTemplate = None
            return
        self.issueTemplate = issueTemplate

    def set_teams_webhook(self, teamsWebhook):
        if teamsWebhook is None:
            self.teamsWebhook = None
            return
        if teamsWebhook == "":
            self.teamsWebhook = None
            return
        if teamsWebhook == "NA":
            self.teamsWebhook = None
            return
        self.teamsWebhook = teamsWebhook

    def teamsEnabled(self):
        return self.teamsWebhook is not None

    def __init__(self):
        self.hasData = False
        self.failBuild = False
        self.teamsWebhook = None
        self.buildName = None
        self.buildNumber = None
        self.issueTemplate = None
    
    def send_message_card(self, messageCard):
        if not self.teamsEnabled():
            return
        
        x = len(messageCard.sections)
        if len(messageCard.sections) > 9:
            messageCard.sections = messageCard.sections[:9]
            section = Section()
            section.activityTitle = "... and {:d} more".format(x-9)
            messageCard.sections.append(section)
        
        data = json.dumps(messageCard, cls=MessageCardEncoder, indent=2)
        dump_strjson_panel("messageCard", data)
        resp = request.post(self.teamsWebhook, data=data, headers={"Content-Type": "application/json"})


        dump_strjson_panel("response", resp.text)

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
            issueObj.issueTemplate = self.issueTemplate
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
            m = ":trophy: 0 critical, 0 high xray vulernabilities for this build - [{:s}]({:s})".format(message, link)
            print("## {:s}".format(m))
            dump_obj_panel("response", data)
            mc = MessageCard(m, "00FF00")
            self.send_message_card(mc)
            exit(0)
        mc = MessageCard("Xray Vulnerabilities", "FF0000")
        if len(crit) > 0:
            m = ":skull: {:d} critical, {:d} high xray vulnerabilities for this build - [{:s}]({:s})".format(len(crit) , len(high),message, link)
            print("## {:s}".format(m))
            mc.title = m
            dump_obj_panel("response", data)
        else:
            m = ":fire: {:d} critical, {:d} high xray vulnerabilities for this build - [{:s}]({:s})".format(len(crit) , len(high),message, link)
            print("## {:s}".format(m))
            mc.title = m
            dump_obj_panel("response", data)


        for c in crit:
            c.print()
            mc.sections.append(c.asSection())
        for h in high:
            h.print()
            mc.sections.append(h.asSection())

        self.send_message_card(mc)

        if self.failBuild:
            exit(1)
        else:
            print("## :warning: XRAY Vulnerabilities found, but build will not be failed")
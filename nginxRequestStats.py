"""
Utility that enables to parse the NGINX logs from the techsupport
extracted from a customer fabric, in order to identify slow API
requests and the potential causes of it.
"""
import os
import sys
import argparse
import fileinput
from datetime import datetime, timedelta, date
import re
import logging
import pickle
import yaml
import statistics
import operator
import ipaddress
from dataclasses import dataclass
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from util import tree, chomp, globalValues, setupPdb, setupLogger # noqa: E402
from util import catchException, natural_sorted, reportAFailure # noqa: E402
from util import parseDnStr # noqa: E402


# Number of fields in a log line
LOGLINESIZE = 8
LOGLINESIZEMIT = 9
LOGSEPARATOR = "||"
SLOWTRANSACTIONDEFAULT = 80
BUCKETINTERVALDEFAULT = 1

INITLINEREGEXP = re.compile('^[0-9]+\|\|[0-9]{2,2}-[0-9]{2,2}-[0-9]{2,2} [0-9]{2,2}:[0-9]{2,2}:[0-9]{2,2}.[0-9]{3,3}'
                            '[+-]{1,1}[0-9]{2,2}:[0-9]{2,2}\|\|')

TSTAMPREGEXP = re.compile('^(.*\.)([0-9]+)(.*$)')


@dataclass
class NginxRequest:
    """
    NGINX request representation
    """
    startTime: datetime
    httpRequestLine: str
    reqId: str
    reqIdLine: str
    endTime: datetime = None
    outCode: str = None
    notifyEventLine: str = None
    totalTime: timedelta = None
    ip: str = None
    url: str = None
    username: str = "<unknown>"

    def __post_init__(self):
        httpRequestLineParts = self.httpRequestLine.translate(self.httpRequestLine.maketrans({'\n':'', '\r':''})).split(';')
        urlParts = []
        for p in httpRequestLineParts:
            if p.startswith(" from "):
                self.ip = p.replace(" from ", "")
            elif p.startswith(" url="):
                uPart = p.replace(" url=", "")
                if uPart:
                    urlParts.append(uPart)
            elif p.startswith(" url options="):
                uPart = p.replace(" url options=", "")
                if uPart:
                    urlParts.append(uPart)
        self.url = "?".join(urlParts)


@dataclass
class PartialRequest:
    """
    Partial Request, that will be correlated with the response in order
    to generate the final item
    """
    startTime: datetime
    httpRequestLine: str


@dataclass
class PartialResponse:
    """
    Partial Response, that will be correlated with the request in order
    to generate the final item
    """
    endTime: datetime
    outCode: str


@dataclass
class NginxProcessingStats:
    """
    Statistics for processing NGINX logs
    """
    discarded: int = 0
    lines: int = 0
    files: int = 0
    requestsProcessed: int = 0
    requestsDuplicated: int = 0
    requestsNotUserInitiated: int = 0
    requestsNotNotified: int = 0
    requestsWithPartialResponses: int = 0
    numOfReqId: int = 0


@dataclass
class AccessProxyProcessingStats:
    """
    Statistics for processing Access Proxy logs
    """
    discarded: int = 0
    lines: int = 0
    files: int = 0
    processed: int = 0


def yamlRepresentObjAsDict(filteredProps=[]):
    def internalRepr(dumper, data):
        internalDict = dict(data.__dict__)
        for filteredProp in filteredProps:
            if filteredProp in internalDict:
                del internalDict[filteredProp]
        node = dumper.represent_dict(internalDict)
        return node
    return internalRepr


def yamlRepresentObjAsStr(dumper, data):
    if data is None:
        data = "null"
    node = dumper.represent_scalar('timedelta', str(data))
    return node


# Register with YAML code a representation for NginxRequest
yaml.add_representer(NginxRequest, yamlRepresentObjAsDict(['httpRequestLine']))
yaml.add_representer(PartialRequest, yamlRepresentObjAsDict())
yaml.add_representer(PartialResponse, yamlRepresentObjAsDict())
yaml.add_representer(timedelta, yamlRepresentObjAsStr)


def yamlPrint(req):
    return yaml.dump(req,
                     indent=4,
                     default_flow_style=False,
                     canonical=False,
                     sort_keys=True)


def fromACIToIsoFormat(tstamp):
    """
    Make the timestamp iso from ACI
    """
    groups = re.match(TSTAMPREGEXP, tstamp)
    res = "{}{}{}".format(groups[1], groups[2][0:6], groups[3])
    return res


@catchException
def processOneLine(line, reminderLines, ctx, filelineno):
    logger = logging.getLogger(globalValues['logger'])
    if INITLINEREGEXP.match(line) and reminderLines:
        logger.warn("Matching a new start, but seems we have some carryover, flushing it")
        logger.warn("ReminderLines are {}".format(reminderLines))
        logger.warn("CurrentLine is {}".format(line))
        ctx["nginxstats"].discarded += 1
        reminderLines = []
    reminderLines.append(line)
    lineToProcess = "".join(reminderLines)
    logLineParts = lineToProcess.split(LOGSEPARATOR)
    if len(logLineParts) < LOGLINESIZE:
        return reminderLines
    reminderLines = []
    if len(logLineParts) > LOGLINESIZEMIT:
        return reminderLines
    # Now we can do processing
    if len(logLineParts) == LOGLINESIZE:
        _pid, _timestamp, _facility, _loglevel, _context, _message, _file, _line = logLineParts
    elif len(logLineParts) == LOGLINESIZEMIT:
        _pid, _timestamp, _facility, _loglevel, _context, _message, _controlBits, _file, _line = logLineParts

    if _facility == "nginx" and _message.startswith("httpmethod="):
        # Identified a line like:
        # 722||2023-11-24T13:30:33.415966213+01:00||nginx||DBG4||||httpmethod=1; from 172.29.199.198; url=/api/aaaRefresh.json; url options=||../common/src/rest/./Request.cc||137
        # At this point we don't expect any further partial processed requests for this same thread, if it happens is likely some error
        if ctx["partialRequest"].get(_pid, None):
            fmtStr = "@{} met an httpmethod for thread:{} while there are still partial data from a previous instance:{}"
            logger.warn(fmtStr.format(filelineno,
                                      _pid,
                                      yamlPrint(ctx["partialRequest"][_pid])))
            del ctx["partialRequest"][_pid]
            ctx["nginxstats"].requestsNotNotified += 1
        ctx["partialRequest"][_pid] = PartialRequest(datetime.fromisoformat(fromACIToIsoFormat(_timestamp)),
                                                     _message)
    elif _facility == "nginx" and _message.startswith("REQ ID ="):
        # Met a line like:
        # 7722||2023-11-24T13:30:33.416080718+01:00||nginx||DBG4||||REQ ID = 0x61000000000000||../common/src/rest/./Request.cc||155
        reqId = int(_message.replace("REQ ID =", "").strip(), 16)
        reqIdStr = "0x{:x}".format(reqId)
        ctx["nginxstats"].numOfReqId += 1
        req = NginxRequest(ctx["partialRequest"][_pid].startTime,
                           ctx["partialRequest"][_pid].httpRequestLine,
                           reqIdStr,
                           filelineno)
        oldReq = ctx["requests"].get(reqId, None)
        if oldReq:
            fmtStr = "Met an already exisiting reqId: {}, existing req:{}"
            logger.warn(fmtStr.format(reqIdStr,
                                      yamlPrint(oldReq)))
            ctx["requests"]["{}-{}".format(req.reqIdLine, reqIdStr)] = oldReq
            ctx["nginxstats"].requestsDuplicated += 1
            del ctx["requests"][reqId]
        ctx["requests"][reqId] = req
        ctx["lastReqIdKnown"] = reqId
        del ctx["partialRequest"]
    elif _facility == "aaa" and _message.startswith("WebToken request user"):
        # Met a line like:
        # 8236||2024-02-02T09:11:48.263271925+01:00||aaa||DBG4||co=doer:255:127:0xff0000002ea41805:1||WebToken request user Cisco_ApicVision (local)||../common/src/rest/./Auth.cc||450
        reqId = ctx["lastReqIdKnown"]
        req = ctx["requests"].get(reqId, None)
        if req:
            req.username = _message.replace("WebToken request user", "").strip()
    elif _facility == "nginx" and _message.startswith("Requested UserCert uni/userext/"):
        # Met a line like:
        # 8236||2024-02-02T09:12:54.304110837+01:00||nginx||DBG4||co=doer:255:127:0xff0000002ea41963:1||Requested UserCert uni/userext/appuser-intersight_dc/usercert-intersight_dc Fingerprint fingerprint Signature fQpRsV2G8p868Cfsc+MD8NRW+r7zcm5KhGqXyXZ0Th/SBQePelH75s1pWzVlI5avL0XiDsIHA0zkWCSbLn9Q8iEiLDe+ubQ0MwM3GTNmbeW11a3Ri68jbi5DjdcIKShX5Af5oztRJf2N+vsUJc40Db4Ua20wpmsH7qUt5OaVJ/M68h/hBLiHSyYzSDbQh7dUG30bVE5qYn36adPhoFGK1mHEYUTTrSAUjFM4iTXPjTi7e3tS0PZnjOV/t8JFC7A3Jk81xWHASBPQQxttWV7tLqj50Ewuzhnhibq+6N1oJFSdASPtbrWWPkJh33x1gBpOhbuKindMe3iA3AQwoQgosQ== Algorithm Version v1.0||../common/src/rest/./Worker.cc||579
        reqId = ctx["lastReqIdKnown"]
        req = ctx["requests"].get(reqId, None)
        if req:
            reqcertDn = _message.split()[2]
            reqcertDnParts = parseDnStr(reqcertDn)
            req.username = reqcertDnParts['appuser']
    elif _facility == "nginx" and _message.startswith("outCode: "):
        # Met a line like:
        # 7790||2023-11-24T13:30:33.569331073+01:00||nginx||DBG4||co=doer:255:127:0xff00000014acca6c:1||outCode: 200||../common/src/rest/./Worker.cc||760
        if ctx["partialResponse"].get(_pid, None):
            fmtStr = "@{} met an outCode for thread:{} while there are still partial data from a previous instance:{}"
            logger.warn(fmtStr.format(filelineno,
                                      _pid,
                                      yamlPrint(ctx["partialResponse"][_pid])))
            ctx["nginxstats"].requestsWithPartialResponses += 1
            del ctx["partialResponse"][_pid]
        ctx["partialResponse"][_pid] = PartialResponse(datetime.fromisoformat(fromACIToIsoFormat(_timestamp)),
                                                       _message.replace("outCode: ", "").strip())
    elif _facility == "nginx" and _message.startswith("notifyEvent data ready 0x"):
        # Met a line like:
        # 7790||2023-11-24T13:30:33.569355991+01:00||nginx||DBG4||co=doer:255:127:0xff00000014acca6c:1||notifyEvent data ready 0x62000000000000||../common/src/rest/./Worker.cc||780
        reqId = int(_message.replace("notifyEvent data ready", "").strip(), 16)
        if reqId:
            req = ctx["requests"].get(reqId, None)
            if req is None:
                fmtStr = "@{} met a notifyEvent without REQ ID for reqIdStr: 0x{:x}"
                logger.debug(fmtStr.format(filelineno,
                                           reqId))
                ctx["nginxstats"].requestsNotUserInitiated += 1
            else:
                req.endTime = ctx["partialResponse"][_pid].endTime
                req.outCode = ctx["partialResponse"][_pid].outCode
                req.notifyEventLine = filelineno
                ctx["nginxstats"].requestsProcessed += 1
                if req.endTime and req.startTime:
                    req.totalTime = req.endTime - req.startTime
        del ctx["partialResponse"][_pid]
    else:
        ctx["nginxstats"].discarded += 1
    return reminderLines


@catchException
def processAccessProxyFiles(fileList, ctx):
    logger = logging.getLogger(globalValues['logger'])
    ctx["accessProxyStats"] = AccessProxyProcessingStats()
    fileinput.close()
    logger.info("Analizing {} files in the list".format(len(fileList)))
    if not fileList:
        logger.info("No Access Proxy Files to process")
        return
    preDirName = ""
    for line in fileinput.input(fileList, openhook=fileinput.hook_compressed):
        if fileinput.isfirstline():
            if os.path.dirname(fileinput.filename()) == preDirName:
                logger.info("Working on file: {}".format(os.path.basename(fileinput.filename())))
            else:
                logger.info("Working on file: {}".format(fileinput.filename()))
                preDirName = os.path.dirname(fileinput.filename())
            ctx["accessProxyStats"].files += 1
        # Chomp the string
        if type(line) is bytes:
            line = line.decode(encoding='UTF-8', errors='ignore')
        line = chomp(line)
        ctx["accessProxyStats"].lines += 1
        # Now process line like:
        # ::ffff:127.0.0.1 - - [22/Feb/2024:13:01:22 +0100] "GET /api/node/class/dnsProv.json HTTP/1.1" 200 248 "-" "Go-http-client/1.1"
        try:
            lineParts = line.split(' ')
            ipAddr = ipaddress.ip_address(lineParts[0])
            ipAddrStr = str(ipAddr)
            if type(ipAddr) is ipaddress.IPv6Address:
                ipAddrStr = str(ipAddr.ipv4_mapped)
            userAgent = lineParts[-1].replace('"', '')
            ctx["accessProxyStats"].processed += 1
            currCoords = "{}:{}".format(fileinput.filename(),
                                        fileinput.fileno())
            ctx["useragent"][ipAddrStr][userAgent] = currCoords
        except Exception as e:
            ctx["accessProxyStats"].discarded += 1
            reportAFailure("Got error: {}".format(e))
    fileinput.close()
    logger.info("Analized:")
    logger.info(yamlPrint(ctx["accessProxyStats"]))
    if logger.isEnabledFor(logging.DEBUG):
        for ipAddr in ctx["useragent"]:
            logger.debug("For IP:{} we have the following User-Agents:{}".format(ipAddr, ",".join(ctx["useragent"][ipAddr].keys())))


@catchException
def processNginxFiles(fileList, ctx):
    logger = logging.getLogger(globalValues['logger'])
    ctx["nginxstats"] = NginxProcessingStats()
    # Initialize ctx['requests'] as a dictionary, so we can
    # immediately spot if there mismatched items
    ctx["requests"] = {}
    logger.info("Analizing {} files in the list".format(len(fileList)))
    if not fileList:
        logger.info("No Nginx Files to process")
        return
    reminderLines = []
    fileinput.close()
    preDirName = ""
    with fileinput.input(fileList, openhook=fileinput.hook_compressed, errors='namereplace') as f:
        try:
            for line in f:
                try:
                    # Chomp the string
                    if type(line) is bytes:
                        line = line.decode(encoding='UTF-8', errors='ignore')
                    line = chomp(line)
                    if fileinput.isfirstline():
                        if os.path.dirname(fileinput.filename()) == preDirName:
                            logger.info("Working on file: {}".format(os.path.basename(fileinput.filename())))
                        else:
                            logger.info("Working on file: {}".format(fileinput.filename()))
                            preDirName = os.path.dirname(fileinput.filename())
                        logger.debug("CountLine Total till now: {}".format(ctx["lines"]))
                        logger.debug("DiscardedLines: {}".format(ctx["discarded"]))
                        ctx["nginxstats"].files += 1
                        logger.debug("Header is: {}".format(line))
                        if not line.startswith("FILE HEADER: Vers ="):
                            logger.error("This file is not a log file, go to next one")
                            fileinput.nextfile()
                    else:
                        if reminderLines is None:
                            reminderLines = []
                        reminderLines = processOneLine(line,
                                                       reminderLines,
                                                       ctx,
                                                       "{}:{}".format(fileinput.filename(),
                                                                      fileinput.filelineno()))
                        if not reminderLines:
                            # Increase the global line number only if the line was complete
                            ctx["nginxstats"].lines += 1
                except Exception as e:
                    logger.error("Met error {} on {}:{}".format(e,
                                                                fileinput.filename(),
                                                                fileinput.filelineno()))
        except Exception as e:
            logger.error("Met error {} on {}".format(e,
                                                     fileinput.filename()))

    fileinput.close()
    logger.info("Analized:")
    logger.info(yamlPrint(ctx["nginxstats"]))


def postProcess(args, ctx):
    """
    Post process the requests identified in ctx
    """
    reporter = logging.getLogger(globalValues['reporter'])
    reqStats = tree()
    reporter.info("="*80)
    reporter.info("Parsing Stats:")
    reporter.info(yamlPrint(ctx["nginxstats"]))
    reporter.info("="*80)
    reporter.debug("Starting to classify {} requests".format(len(ctx['requests'])))
    if args.reportPerIp:
        reporter.info("Report compiled for IP: {}".format(args.reportPerIp))
    counter = 0
    for reqId in ctx['requests']:
        counter = counter + 1
        req = ctx['requests'][reqId]
        if args.reportPerIp:
            if req.ip != args.reportPerIp:
                continue
        if args.beforeDate:
            if req.startTime.date() > args.beforeDate:
                continue
        if args.afterDate:
            if req.startTime.date() < args.afterDate:
                continue
        try:
            totalTime = req.totalTime
            outCode = req.outCode
            if totalTime is None:
                ctx['incompleteRequestsURL'][req.url][req.ip][reqId] = req.startTime
                continue
            else:
                bucket = totalTime.seconds // args.timeBucket
                reqStats["duration"][bucket][req.reqIdLine] = req
            if outCode:
                reqStats["outCode"][outCode][req.reqIdLine] = req
            if req.startTime:
                reqStats["date"][str(req.startTime.date())][req.reqIdLine] = req
                reqStats["datehour"][str(req.startTime.date())][req.startTime.hour][req.reqIdLine] = req
            if req.ip:
                reqStats["ip"][req.ip][req.reqIdLine] = req
                if req.startTime:
                    reqStats["dateip"][str(req.startTime.date())][req.ip][req.reqIdLine] = req
                    reqStats["datehourip"][str(req.startTime.date())][req.startTime.hour][req.ip][req.reqIdLine] = req
        except Exception as e:
            errStr = "Error: {} processing reqId: {} req: {} counter:{}"
            reporter.error(errStr.format(e, reqId,
                                         yamlPrint(req),
                                         counter))
    reporter.info("="*80)
    reporter.info("Requests by outCode")
    reporter.info("="*80)
    for outCode in sorted(reqStats["outCode"].keys()):
        fmtStr = "OutCode: {} has: {}"
        reporter.info(fmtStr.format(outCode,
                                    len(reqStats["outCode"][outCode])))
    reporter.info("="*80)
    reporter.info("Request stats by IP Address")
    reporter.info("="*80)
    for ip in sorted(reqStats["ip"].keys()):
        reporter.info("From IP: {} we got: {} from user-agents: {}".format(ip,
                                                                           len(reqStats["ip"][ip].keys()),
                                                                           "\n\t".join(ctx["useragent"][ip].keys())))
    for d in sorted(reqStats["date"].keys()):
        reporter.info("="*80)
        reporter.info("Request stats for day: {}".format(d))
        reporter.info("="*80)
        respTimesPerDay = [getattr(o, 'totalTime').total_seconds() for o in reqStats["date"][d].values()]
        reporter.info("Average response time: {}".format(statistics.mean(respTimesPerDay)))
        reporter.info("Max response time: {}".format(max(respTimesPerDay)))
        reporter.info("Min response time: {}".format(min(respTimesPerDay)))
        reporter.info("Num of requests: {}".format(len(respTimesPerDay)))
        for ip in sorted(reqStats["dateip"][d].keys()):
            reporter.info("From IP: {} we got: {}".format(ip,
                                                          len(reqStats["dateip"][d][ip].keys())))
        for hour in sorted(reqStats["datehour"][d].keys()):
            respTimesPerHour = [getattr(o, 'totalTime').total_seconds() for o in reqStats["datehour"][d][hour].values()]
            reporter.info("\t{}".format("~"*40))
            reporter.info("\tRequest stats for Hour: {}".format(hour))
            reporter.info("\t{}".format("~"*40))
            reporter.info("\t\tAverage response time: {}".format(statistics.mean(respTimesPerHour)))
            reporter.info("\t\tMax response time: {}".format(max(respTimesPerHour)))
            reporter.info("\t\tMin response time: {}".format(min(respTimesPerHour)))
            reporter.info("\t\tNum of requests: {}".format(len(respTimesPerHour)))
            for ip in sorted(reqStats["datehourip"][d][hour].keys()):
                respTimesPerHourIp = [getattr(o, 'totalTime').total_seconds() for o in reqStats["datehourip"][d][hour][ip].values()]
                reporter.info("\t\t{}".format("."*40))
                reporter.info("\t\tFrom IP: {}".format(ip))
                reporter.info("\t\t{}".format("."*40))
                reporter.info("\t\t\tAverage response time: {}".format(statistics.mean(respTimesPerHourIp)))
                reporter.info("\t\t\tMax response time: {}".format(max(respTimesPerHourIp)))
                reporter.info("\t\t\tMin response time: {}".format(min(respTimesPerHourIp)))
                reporter.info("\t\t\tNum of requests: {}".format(len(respTimesPerHourIp)))

    for bucket in sorted(reqStats["duration"].keys()):
        fmtStr = "Responses from:{} secs to :{} secs has: {} elements"
        reporter.info("="*80)
        reporter.info(fmtStr.format(bucket*args.timeBucket,
                                    (bucket+1)*args.timeBucket,
                                    len(reqStats["duration"][bucket].keys())))
        reporter.info("="*80)
        if not args.allTransactions:
            if bucket*args.timeBucket <= args.slowTransaction:
                continue
        for req in sorted(reqStats["duration"][bucket].values(),
                          key=operator.attrgetter('totalTime')):
            reporter.info("\n{}".format(yamlPrint(req)))
    reporter.info("="*80)
    reporter.info("Requests classified as incomplete")
    reporter.info("="*80)
    urlSet = sorted(ctx['incompleteRequestsURL'].keys())
    totalNumIncompleteReq = 0
    reporter.info("Number of unique URLs: {}".format(len(urlSet)))
    for u in urlSet:
        reporter.info("\t{}".format(u))
        for ipAdd in ctx['incompleteRequestsURL'][u]:
            reporter.info("\t\t{}".format(ipAdd))
            totalNumIncompleteReq += len(ctx['incompleteRequestsURL'][u][ipAdd].values())
    reporter.info("Number classified as incomplete: {}".format(totalNumIncompleteReq))


@catchException
def doMain():
    parser = argparse.ArgumentParser("Perfom NGIN request/response slow analysis and identify common causes of issues")
    parser.add_argument('--pattern',
                        help='File pattern matching for NGINX logs',
                        default=r'nginx\.bin\.log\.[0-9]+\.*')
    parser.add_argument('--accessProxyPattern',
                        help='File pattern matching for access proxy',
                        default=r'accessproxy.log.*')
    parser.add_argument('-r',
                        '--rootDir',
                        help='Directory where to start from the analysis',
                        default='.')
    parser.add_argument('--pickleCtx',
                        help='Name of the pickle file where to save the context for quick reanalysis without doing a reparsing',
                        default='nginxRequestStatsIntermediate.pickle')
    parser.add_argument('--forceReparse',
                        help='Reparse the data even if pre-parsed file exists',
                        action="store_true",
                        default=False)
    parser.add_argument('--pdb',
                        help='In case of issues invoke pdb',
                        action="store_true",
                        default=False)
    parser.add_argument('--debug',
                        help='Debug info',
                        action="store_true",
                        default=False)
    parser.add_argument('--timeBucket',
                        help='Size of a time interval in which to classify the requests, default: {} sec.'.format(BUCKETINTERVALDEFAULT),
                        default=BUCKETINTERVALDEFAULT)
    parser.add_argument('--slowTransaction',
                        help='Transaction during more that this parameter will be consider slow, default: {} sec.'.format(SLOWTRANSACTIONDEFAULT),
                        type=int,
                        default=SLOWTRANSACTIONDEFAULT)
    parser.add_argument('--allTransactions',
                        help='Report all the transactions',
                        action="store_true",
                        default=False)
    parser.add_argument('--reportPerIp',
                        help='FilterReportPerIP',
                        default=None)
    parser.add_argument('--afterDate',
                        help='Filter all the requests initiated after a certain date, in ISOformat - YYYY-MM-DD',
                        type=date.fromisoformat,
                        default=None)
    parser.add_argument('--beforeDate',
                        help='Filter all the requests initiated before a certain date, in ISOformat - YYYY-MM-DD',
                        type=date.fromisoformat,
                        default=None)
    parser.add_argument('--quiet',
                        help='Avoid any output',
                        action="store_true",
                        default=False)
    parser.add_argument('--logToFile',
                        help='File to log to',
                        default=None)
    parser.add_argument('--logLevel',
                        help='Level for logging info',
                        default=logging.INFO,
                        choices=logging._nameToLevel.keys())

    args = parser.parse_args()
    setupLogger(args)
    setupPdb(args)
    logger = logging.getLogger(globalValues['logger'])
    nginxFileList = []
    accessProxyFileList = []
    args.pattern = args.pattern.replace("'", "")
    nginxRMatch = re.compile(args.pattern)
    accessProxyRMatch = re.compile(args.accessProxyPattern)
    for root, dirs, files in os.walk(args.rootDir):
        if "/log.lastupgrade/" in root or root.endswith('/log.lastupgrade'):
            logger.debug("Skipping: {}".format(root))
            continue
        for fileName in files:
            if re.match(nginxRMatch, fileName):
                nginxFileList.append(os.path.join(root, fileName))
            elif re.match(accessProxyRMatch, fileName):
                accessProxyFileList.append(os.path.join(root, fileName))
    if not nginxFileList:
        print("No file(s) to analize")
        return -1
    nginxFileList = natural_sorted(list(nginxFileList))
    accessProxyFileList = natural_sorted(list(accessProxyFileList))
    pickleFile = os.path.join(args.rootDir, args.pickleCtx)
    ctx = None
    if args.forceReparse:
        if os.path.exists(pickleFile):
            os.unlink(pickleFile)
    if os.path.exists(pickleFile):
        with open(pickleFile, "rb") as pickleF:
            logger.info("Loading the pre-parsed data from: {}".format(pickleFile))
            ctx = pickle.load(pickleF)
    else:
        ctx = tree()
        processAccessProxyFiles(accessProxyFileList, ctx)
        processNginxFiles(nginxFileList, ctx)
        if not os.path.exists(pickleFile):
            with open(pickleFile, "wb") as pickleF:
                pickle.dump(ctx, pickleF)
                logger.info("Wrote parsed data in: {}".format(pickleFile))
    # Now do some Stats analysis on the pre-parsed ctx
    postProcess(args, ctx)
    return 0


if __name__ == '__main__':
    sys.exit(doMain())

"""
Utility that enables to parse the NGINX logs from the techsupport
extracted from a customer fabric, in order to identify slow API
requests and the potential causes of it.
"""
import os
import sys
import argparse
import fileinput
import natsort
from datetime import datetime, timedelta
import re
import logging
import pickle
import yaml
import statistics
import operator
from dataclasses import dataclass
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from util import tree, chomp, globalValues, setupPdb, setupLogger, catchException


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

    def __post_init__(self):
        httpRequestLineParts = self.httpRequestLine.translate(self.httpRequestLine.maketrans({'\n':'', '\r':''})).split(';')
        urlParts = []
        for p in httpRequestLineParts:
            if p.startswith(" from "):
                self.ip = p.replace(" from ", "")
            elif p.startswith(" url="):
                urlParts.append(p.replace(" url=", ""))
            elif p.startswith(" url options="):
                urlParts.append(p.replace(" url options=", ""))
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
class ProcessingStats:
    """
    Statistics for processing
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
        ctx["stats"].discarded += 1
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
            ctx["stats"].requestsNotNotified += 1
        ctx["partialRequest"][_pid] = PartialRequest(datetime.fromisoformat(fromACIToIsoFormat(_timestamp)),
                                                     _message)
    elif _facility == "nginx" and _message.startswith("REQ ID ="):
        # Met a line like:
        # 7722||2023-11-24T13:30:33.416080718+01:00||nginx||DBG4||||REQ ID = 0x61000000000000||../common/src/rest/./Request.cc||155
        reqId = int(_message.replace("REQ ID =", "").strip(), 16)
        reqIdStr = "0x{:x}".format(reqId)
        ctx["stats"].numOfReqId += 1
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
            ctx["stats"].requestsDuplicated += 1
            del ctx["requests"][reqId]
        ctx["requests"][reqId] = req
        del ctx["partialRequest"]
    elif _facility == "nginx" and _message.startswith("outCode: "):
        # Met a line like:
        # 7790||2023-11-24T13:30:33.569331073+01:00||nginx||DBG4||co=doer:255:127:0xff00000014acca6c:1||outCode: 200||../common/src/rest/./Worker.cc||760
        if ctx["partialResponse"].get(_pid, None):
            fmtStr = "@{} met an outCode for thread:{} while there are still partial data from a previous instance:{}"
            logger.warn(fmtStr.format(filelineno,
                                      _pid,
                                      yamlPrint(ctx["partialResponse"][_pid])))
            ctx["stats"].requestsWithPartialResponses += 1
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
                ctx["stats"].requestsNotUserInitiated += 1
            else:
                req.endTime = ctx["partialResponse"][_pid].endTime
                req.outCode = ctx["partialResponse"][_pid].outCode
                req.notifyEventLine = filelineno
                ctx["stats"].requestsProcessed += 1
                if req.endTime and req.startTime:
                    req.totalTime = req.endTime - req.startTime
        del ctx["partialResponse"][_pid]
    else:
        ctx["stats"].discarded += 1
    return reminderLines


@catchException
def processFiles(fileList, ctx):
    logger = logging.getLogger(globalValues['logger'])
    ctx["stats"] = ProcessingStats()
    # Initialize ctx['requests'] as a dictionary, so we can
    # immediately spot if there mismatched items
    ctx["requests"] = {}
    logger.info("Analizing {} files in the list".format(len(fileList)))
    reminderLines = []
    fileinput.close()
    preDirName = ""
    for line in fileinput.input(fileList, openhook=fileinput.hook_compressed):
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
            ctx["stats"].files += 1
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
                ctx["stats"].lines += 1
    fileinput.close()
    logger.info("Analized:")
    logger.info(yamlPrint(ctx["stats"]))


def postProcess(args, ctx):
    """
    Post process the requests identified in ctx
    """
    reporter = logging.getLogger(globalValues['reporter'])
    reqStats = tree()
    reporter.info("="*80)
    reporter.info("Parsing Stats:")
    reporter.info(yamlPrint(ctx["stats"]))
    reporter.info("="*80)
    reporter.debug("Starting to classify {} requests".format(len(ctx['requests'])))
    counter = 0
    for reqId in ctx['requests']:
        counter = counter + 1
        req = ctx['requests'][reqId]
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
        reporter.info("From IP: {} we got: {}".format(ip, len(reqStats["ip"][ip].keys())))
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
    parser.add_argument('-p',
                        '--pattern',
                        help='File pattern matching',
                        default=r'nginx\.bin\.log\.[0-9]+\.*')
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
    fileList = []
    args.pattern = args.pattern.replace("'", "")
    rmatch = re.compile(args.pattern)
    logger.debug('Pattern is {}'.format(args.pattern))
    for root, dirs, files in os.walk(args.rootDir):
        if "/log.lastupgrade/" in root or root.endswith('/log.lastupgrade'):
            logger.debug("Skipping: {}".format(root))
            continue
        for fileName in files:
            if re.match(rmatch, fileName):
                fileList.append(os.path.join(root, fileName))
    if not fileList:
        print("No file(s) to analize")
        return -1
    fileSet = set(fileList)
    fileList = natsort.natsorted(list(fileSet))
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
        processFiles(fileList, ctx)
        if not os.path.exists(pickleFile):
            with open(pickleFile, "wb") as pickleF:
                pickle.dump(ctx, pickleF)
                logger.info("Wrote parsed data in: {}".format(pickleFile))
    # Now do some Stats analysis on the pre-parsed ctx
    postProcess(args, ctx)
    return 0


if __name__ == '__main__':
    sys.exit(doMain())

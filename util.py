import sys
from collections import defaultdict
import pdb
import functools
import logging


def tree():
    """
    Define a tree like structure
    """
    return defaultdict(tree)


globalValues = tree()


def chomp(x):
    if x.endswith("\r\n"):
        return x[:-2]
    if x.endswith("\n") or x.endswith("\r"):
        return x[:-1]
    return x


def catchException(fn):
    """
    A decorator that wraps the passed in function and logs
    exceptions should one occur
    """
    @functools.wraps(fn)
    def wrapperFn(*args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:
            if globalValues['usepdb']:
                pdb.post_mortem()
            logger = logging.getLogger(globalValues['logger'])
            logger.error("Error while executing function:{} with args:{} kargs:{}".format(fn, args, kwargs))
            logger.exception(e)
    return wrapperFn


def reportAFailure(msg):
    if globalValues['usepdb']:
        pdb.post_mortem()
    else:
        raise Exception(msg)


def setupLogger(args):
    """
    Routine to setup the logger as normally used in scripts
    """
    # "logger" is used to log with timestamp and loglevel, as expected
    formatter = logging.Formatter(
        fmt='%(asctime)s%(msecs)d %(levelname)-8s %(message)s')
    globalValues['logger'] = "logger"
    logger = logging.getLogger(globalValues['logger'])
    logLevelToUse = args.logLevel
    if args.debug:
        logLevelToUse = logging.DEBUG
    if not args.quiet:
        nameOfLevel = logLevelToUse
        if logging._nameToLevel.get(nameOfLevel, None) is None:
            nameOfLevel = logging._levelToName.get(nameOfLevel)
        print("Log Level set to: {}".format(nameOfLevel))
    logger.setLevel(logLevelToUse)
    if not args.quiet:
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    if args.logToFile:
        fh = logging.FileHandler(args.logToFile, mode="a")
        fh.setLevel(logLevelToUse)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # "reporter" is used to essentially print, but without timestamps,
    # on the same location used by the logger
    reporterFormatter = logging.Formatter(
        fmt='%(message)s')
    globalValues['reporter'] = "reporter"
    reporter = logging.getLogger(globalValues['reporter'])
    reporter.setLevel(logLevelToUse)
    if not args.quiet:
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setFormatter(reporterFormatter)
        reporter.addHandler(ch)
    if args.logToFile:
        fh = logging.FileHandler(args.logToFile, mode="a")
        fh.setLevel(logLevelToUse)
        fh.setFormatter(reporterFormatter)
        reporter.addHandler(fh)


def setupPdb(args):
    """
    Routine to setup the PDB as normally used in scripts
    """
    globalValues['usepdb'] = args.pdb


if __name__ == "__main__":
    print("{} can only be included".format(__file__))
    sys.exit(-1)

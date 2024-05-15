import sys
from collections import defaultdict
import pdb
import functools
import logging
import re

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


@functools.cache
def parseDnStr(dnStr, returnList=False):
    '''
    Routine that will split a dn formatted string for example:
    uni/tn-foo/ap-ap1/epg-e1/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/1]]
    in a dictionary with:
    {
    'uni': ''
    'tn': 'foo'
    'ap': 'ap1'
    'epg': 'e1'
    'rspathAtt': '[topology/pod-1/paths-101/pathep-[eth1/1]]'
    }
    if the same routine is executed again on:
    'topology/pod-1/paths-101/pathep-[eth1/1]'
    that would yield:
    {
    'topology': ''
    'pod': '1'
    'paths': '101'
    'pathep': '[eth1/1]'
    }
    if returnList parameter is TRUE instead of a dictionary a list of
    the dn parts will be returned
    '''

    def matches(line):
        '''
        Matches the top level pairs of [] so for example in a string
        like:
        '[foo]/[[baz]]'
        will return the position of:
        [ {'start': 1, 'end': 4},
          {'start': 7, end: '12'} ]
        this because will match the content of '[foo]' that is 'foo'
        and the content of '[[baz]]' which is '[baz]' ignoring any
        level of nesting below. The list returned will be in such a
        way that will start from the lower positions
        '''
        stack = []
        retList = []
        import re
        for m in re.finditer(r'[\[\]]', line):
            pos = m.start()
            if line[pos-1] == '\\':
                continue
            c = line[pos]
            if c == '[':
                stack.append(pos+1)
            elif c == ']':
                if len(stack) > 0:
                    prevpos = stack.pop()
                    # Report the top level pairs
                    if len(stack) == 0:
                        retItem = {}
                        retItem['start'] = prevpos
                        retItem['end'] = pos
                        retList.append(retItem)
                else:
                    errStr = "extraneous closing quote at pos {}: '{}'"
                    raise ValueError(errStr.format(pos, line[pos:]))
        if len(stack) > 0:
            for pos in stack:
                errStr = "expecting closing quote to match open quote at: '{}'"
                raise ValueError(errStr.format(line[pos-1:]))
        return retList

    res = {}
    resList = []
    if dnStr is None:
        return res
    # Make sure it's a string
    dnStr = str(dnStr)
    topLevelMatches = matches(dnStr)
    dnStrStrippedList = []
    piecesToReinsert = {}
    prevEnd = 0
    for match in topLevelMatches:
        currStart = match['start']
        currEnd = match['end']
        dnStrStrippedList.append(dnStr[prevEnd:currStart])
        bookmark = 'start{}'.format(currStart)
        # Now add a bookmark so we can readd what we are trimming off
        dnStrStrippedList.append('{')
        dnStrStrippedList.append(bookmark)
        dnStrStrippedList.append('}')
        piecesToReinsert[bookmark] = dnStr[currStart:currEnd]
        prevEnd = currEnd
    # Attach the rest of the string
    dnStrStrippedList.append(dnStr[prevEnd:])
    dnStrStripped = ''.join(dnStrStrippedList)
    # Split the string yanked of the inner [] content because that
    # string would contain '/' which would cause wrong parsing of the
    # level
    rnList = dnStrStripped.split('/')
    for rn in rnList:
        resList.append(rn.format(**piecesToReinsert))
        # Split only the first - if present
        rnKeyVal = rn.split('-', 1)
        # Now lets compile the result where we can have just a key or
        # a key/value in both the cases there could be a marker like
        # [{start<X>}] that need to be refilled with the pieces we
        # yanked before the split
        if len(rnKeyVal) == 1:
            res[rnKeyVal[0].format(**piecesToReinsert)] = ''
        if len(rnKeyVal) == 2:
            res[rnKeyVal[0].format(**piecesToReinsert)] = rnKeyVal[1].format(
                **piecesToReinsert)
        # In other cases, we silently ignore it, field is malformed
    if returnList:
        return resList
    else:
        return res


# Copyright (C) 2018, Benjamin Drung <bdrung@posteo.de>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# https://github.com/bdrung/snippets/blob/main/natural_sorted.py
def natural_sorted(iterable, key=None, reverse=False):
    """Return a new naturally sorted list from the items in *iterable*.

    The returned list is in natural sort order. The string is ordered
    lexicographically (using the Unicode code point number to order individual
    characters), except that multi-digit numbers are ordered as a single
    character.

    Has two optional arguments which must be specified as keyword arguments.

    *key* specifies a function of one argument that is used to extract a
    comparison key from each list element: ``key=str.lower``.  The default value
    is ``None`` (compare the elements directly).

    *reverse* is a boolean value.  If set to ``True``, then the list elements are
    sorted as if each comparison were reversed.

    The :func:`natural_sorted` function is guaranteed to be stable. A sort is
    stable if it guarantees not to change the relative order of elements that
    compare equal --- this is helpful for sorting in multiple passes (for
    example, sort by department, then by salary grade).
    """
    prog = re.compile(r"(\d+)")

    def alphanum_key(element):
        """Split given key in list of strings and digits"""
        return [int(c) if c.isdigit() else c for c in prog.split(key(element)
                                                                 if key else element)]

    return sorted(iterable, key=alphanum_key, reverse=reverse)


if __name__ == "__main__":
    print("{} can only be included".format(__file__))
    sys.exit(-1)

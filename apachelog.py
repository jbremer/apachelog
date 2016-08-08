import re
import urlparse

# regex query to parse one apache log entry
# modified version of the query that can be found at the following blogpost
# http://scalability.org/?p=3802
APACHE_LOG_ENTRY = re.compile(
    r'(\d+.\d+.\d+.\d+)\s+(\S+)\s+(\S+)\s+\[(\d+\/\S+\/\d+):(\d+:\d+:\d+)' +
    r'\s+([-+]{0,1}\d+)\]\s+\"(\S+)\s+(\S+)\s+HTTP\/\d+\.\d+\"\s+(\d+)\s+' +
    r'(\S+)\s+\"(.*?)\"\s+\"(.*?)\"')


class Request:
    def __init__(self, result):
        self.ip = result[0]
        self.date = result[3]
        self.time = result[4]
        self.method = result[6]
        self.uri = result[7]
        self.response_code = result[8]
        self.content_length = int(result[9]) if result[9] != '-' else 0
        self.referer = result[10] if result[10] != '-' else None
        self.user_agent = result[11] if result[11] != '-' else None

        # if there's a referer, urlparse it, and extract the query into a dict
        if self.referer:
            self.referer = urlparse.urlparse(self.referer)
            self.referer.kwargs = self._parse_get(self.referer.query)

        if self.uri:
            self.uri = urlparse.urlparse(self.uri)
            self.uri.kwargs = self._parse_get(self.uri.query)

    def _parse_get(self, query):
        # convert a query to a key-value dictionary
        ret = dict((x.split('=', 1) if x.count('=') else (x, ''))
                   for x in query.split('&') if x)

        # urldecode each value (i.e., decode whitespaces)
        return dict((k, v.replace('%20', ' ').replace('+', ' '))
                    for k, v in ret.items())


def enumerate(fname):
    for line in open(fname):
        result = APACHE_LOG_ENTRY.match(line)
        if result:
            yield Request(result.groups())

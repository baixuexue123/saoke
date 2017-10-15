#!/usr/bin/env python3
import hashlib

import tornado.web
import tornado.ioloop
import tornado.httpserver
from tornado import gen
from tornado.options import define, options, parse_command_line
from tornado.log import app_log as logger

from utils.text import force_bytes


class Index(tornado.web.RequestHandler):
    @gen.coroutine
    def get(self):
        self.set_status(200)
        self.set_header("Content-Type", "text/html")
        self.write("<p>Welcome to Pysaoke's API</p>")


class WxSignature(tornado.web.RequestHandler):
    """微信服务器签名验证, 消息回复
    check_signature: 校验signature是否正确
    """

    @gen.coroutine
    def get(self):
        signature = self.get_argument('signature')
        timestamp = self.get_argument('timestamp')
        nonce = self.get_argument('nonce')
        echostr = self.get_argument('echostr')

        logger.debug(f'微信sign校验, signature={signature}&timestamp={timestamp}&nonce={nonce}&echostr={echostr}')
        ok = self.check_signature(signature, timestamp, nonce)
        if ok:
            logger.debug('微信sign校验, 返回echostr='+echostr)
            self.write(echostr)
        else:
            logger.error('微信sign校验,---校验失败')

    def check_signature(self, signature, timestamp, nonce):
        """校验token是否正确"""
        token = 'pysaoke123'
        L = [timestamp, nonce, token]
        L.sort()
        s = L[0] + L[1] + L[2]
        sha1 = hashlib.sha1(force_bytes(s)).hexdigest()
        logger.debug(f'sha1={sha1}&signature={signature}')
        return sha1 == signature


def make_app(debug=False):
    return tornado.web.Application([
        (r"/", Index),
        (r"/signature", WxSignature),
    ], debug=debug)


def main():
    define("debug", default=False, help="Debug mode", type=bool)
    define("port", default=8000, help="run on the given port", type=int)
    parse_command_line()

    app = make_app(options.debug)
    server = tornado.httpserver.HTTPServer(app)
    server.listen(options.port, address="127.0.0.1")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()

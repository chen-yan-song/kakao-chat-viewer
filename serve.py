#!/usr/bin/env python3
"""本地静态服务器（禁缓存），用于开发验证。
浏览器静态模块缓存会干扰开发调试，这里统一加 Cache-Control: no-store。
"""
import http.server
import socketserver

PORT = 8765


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def do_GET(self):
        # 忽略条件请求头，始终返回 200 全量内容（避免 304 命中浏览器旧缓存）
        for key in ('If-Modified-Since', 'If-None-Match'):
            if key in self.headers:
                del self.headers[key]
        super().do_GET()


if __name__ == '__main__':
    with socketserver.TCPServer(('', PORT), NoCacheHandler) as httpd:
        print(f'KakaoChat Viewer 开发服务器已启动: http://localhost:{PORT}')
        httpd.serve_forever()

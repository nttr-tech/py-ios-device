import atexit
import logging
import os
import queue
import re
import sys
import socket
import threading
import time

from flask import Flask, jsonify, request
from werkzeug.serving import WSGIRequestHandler


class IOSTunnelServer:
    def __init__(self):
        self.sessions = {}
        self.tunnel_process = None
        self.app = Flask(__name__)
        self.setup_routes()
        self.output_queue = queue.Queue()
        self.monitor_thread = None
        self.flask_thread = None
        self.should_run = threading.Event()
        self.should_run.set()
        self.cleanup_done = False
        self.port = 3333
        self.logger = self.setup_logger()
        self.configure_flask_logging()

    def setup_logger(self):
        class StderrFilter(logging.Filter):
            def filter(self, record):
                return record.levelno >= logging.WARNING

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file_path = os.path.join(os.getcwd(), 'ios_tunnel_server.log')

        # File handler for all levels
        fh = logging.FileHandler(log_file_path)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.WARNING)
        stderr_handler.setFormatter(formatter)
        stderr_handler.addFilter(StderrFilter())
        logger.addHandler(stderr_handler)

        # Prevent propagation to avoid duplicate logging
        logger.propagate = False
        return logger

    def configure_flask_logging(self):
        # Disable Flask's default logger
        self.app.logger.disabled = True

        # Configure Werkzeug logging
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all levels

        # Remove any existing handlers (including the default StreamHandler)
        for handler in werkzeug_logger.handlers[:]:
            werkzeug_logger.removeHandler(handler)

        # Redirect Werkzeug logs to file
        werkzeug_log_path = os.path.join(os.getcwd(), 'werkzeug.log')
        werkzeug_handler = logging.FileHandler(werkzeug_log_path)
        werkzeug_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        werkzeug_handler.setFormatter(formatter)
        werkzeug_logger.addHandler(werkzeug_handler)

        # Prevent Werkzeug logs from propagating to the root logger
        werkzeug_logger.propagate = False

        # Suppress Werkzeug's console output by overriding its log function
        def custom_log_request(self, *args, **kwargs):
            pass

        WSGIRequestHandler.log_request = custom_log_request

    def setup_routes(self):
        @self.app.route('/sessions', methods=['GET'])
        def get_sessions():
            self.logger.debug(f'Returning current sessions: {self.sessions}')
            return jsonify(self.sessions)

        @self.app.route('/shutdown', methods=['POST'])
        def shutdown():
            self.should_run.clear()
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return 'Server shutting down...'

    def is_port_in_use(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', self.port)) == 0

    def get_pymobiledevice3_path(self):
        pymobiledevice3_path = '/usr/local/rtk/osx/ios17/bin/pymobiledevice3'
        if not os.path.exists(pymobiledevice3_path):
            pymobiledevice3_path = '/usr/local/rte/osx/ios17/bin/pymobiledevice3'
            if not os.path.exists(pymobiledevice3_path):
                return None
        return pymobiledevice3_path

    def start_tunnel_process(self):
        pymobiledevice3_path = self.get_pymobiledevice3_path()
        if not pymobiledevice3_path:
            self.logger.error(f'pymobiledevice3 executable not found at: {pymobiledevice3_path}')
            return False
        cmd = f'sudo {pymobiledevice3_path} remote tunneld --usbmux --no-usb --no-wifi --no-mobdev2 > /tmp/ios_tunnel.log 2>&1 &'
        self.logger.info(f'Starting iOS tunnel process with command: {cmd}')

        try:
            exit_code = os.system(cmd)
            if exit_code != 0:
                raise OSError(f'Command failed with exit code: {exit_code}')

            time.sleep(2)
            with open('/tmp/ios_tunnel.log', 'r') as log_file:
                log_content = log_file.read()
                if "Error" in log_content or "Failed" in log_content:
                    raise OSError(f"Failed to start tunnel process. Log content: {log_content}")

            self.logger.info('iOS tunnel process started successfully')
            return True
        except OSError as e:
            self.logger.error(f'Failed to start iOS tunnel process: {e}')
            return False
        except Exception as e:
            self.logger.error(f'Unexpected error while starting iOS tunnel process: {e}')
            return False

    def parse_connection_info(self, line):
        udid_match = re.search(r'usbmux-([\w\-]+)', line)
        host_match = re.search(r'--rsd ([\w:]+)', line)
        port_match = re.search(r'(\d+)$', line)

        if udid_match and host_match and port_match:
            udid = udid_match.group(1)
            udid = udid.replace('-USB', '')
            return {
                'udid': udid,
                'host': host_match.group(1),
                'port': int(port_match.group(1))
            }
        return None

    def parse_disconnection_info(self, line):
        host_match = re.search(r'--rsd ([\w:]+)', line)
        port_match = re.search(r'(\d+)$', line)

        if host_match and port_match:
            for key, value in self.sessions.items():
                if value['host'] == host_match.group(1) and value['port'] == int(port_match.group(1)):
                    return value
        return None

    def output_reader(self):
        with open('/tmp/ios_tunnel.log', 'r') as log_file:
            while self.should_run.is_set():
                line = log_file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                self.output_queue.put(line.strip())

    def monitor_connections(self):
        self.logger.info('Starting to monitor connections')
        self.monitor_thread = threading.Thread(target=self.output_reader)
        self.monitor_thread.start()

        while self.should_run.is_set():
            try:
                line = self.output_queue.get(timeout=1)
                # self.logger.debug(f"pymobiledevice3-output: {line}")
                if 'Created tunnel' in line:
                    connection_info = self.parse_connection_info(line)
                    if connection_info:
                        self.sessions[connection_info['udid']] = connection_info
                        self.logger.info(f'New session added: {connection_info}')
                elif 'disconnected from tunnel' in line:
                    disconnected_session = self.parse_disconnection_info(line)
                    if disconnected_session:
                        removed_session = self.sessions.pop(disconnected_session['udid'], None)
                        if removed_session:
                            self.logger.info(f'Session removed: {removed_session}')
                        else:
                            self.logger.warning(f'Tried to remove non-existent session: {disconnected_session}')
            except queue.Empty:
                continue

    def stop_tunnel_process(self):
        self.logger.info('Stopping iOS tunnel process')
        cmd = 'sudo pkill -9 pymobiledevice3'
        exit_code = os.system(cmd)

        if exit_code == 0:
            self.logger.info('Successfully killed pymobiledevice3 processes')
        else:
            self.logger.warning(f'Failed to kill pymobiledevice3 processes. Exit code: {exit_code}')

    def run_flask_app(self):
        self.logger.info('Starting Flask app')
        self.app.run(host='localhost', port=self.port, threaded=True, use_reloader=False)

    def cleanup(self):
        if self.cleanup_done:
            return
        self.logger.info('Cleaning up before exit')
        self.should_run.clear()
        self.stop_tunnel_process()
        if self.flask_thread and self.flask_thread.is_alive():
            import ctypes
            ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(self.flask_thread.ident), ctypes.py_object(SystemExit))
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=3)
        self.cleanup_done = True

    def run(self):
        if self.is_port_in_use():
            self.logger.info(f'Port {self.port} is already in use. Another instance might be running.')
            return

        atexit.register(self.cleanup)
        if not self.start_tunnel_process():
            self.logger.error('Failed to start tunnel process. Exiting.')
            return

        self.flask_thread = threading.Thread(target=self.run_flask_app)
        self.flask_thread.start()
        try:
            self.monitor_connections()
        except KeyboardInterrupt:
            self.logger.info('Received KeyboardInterrupt, stopping services')
        finally:
            self.cleanup()

def main():
    if len(sys.argv) < 2:
        print('Usage: python3 ios_tunnel_server.py [start|stop]')
        sys.exit(1)

    action = sys.argv[1]
    server = IOSTunnelServer()

    if action == 'start':
        server.logger.info('Starting iOS Tunnel Server and Flask app')
        server.run()
    elif action == 'stop':
        server.logger.info('Stopping iOS Tunnel Server')
        server.cleanup()
    else:
        server.logger.error(f"Invalid action: {action}. Use 'start' or 'stop'.")

if __name__ == '__main__':
    main()

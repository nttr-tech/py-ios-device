import json
import logging
import os
import signal
import socket
import sys
import threading
import time

import requests

from ios_device.remote.remote_lockdown import RemoteLockdownClient
from ios_device.servers.Instrument import InstrumentServer


class GracefulExit(Exception):
    pass


class IOS17Sysmontap:
    def __init__(self, rpc, logger):
        self.rpc = rpc
        self.logger = logger
        self.setup_monitoring()

    def dropped_message(self, res):
        self.logger.debug(f'[DROP] {res.selector} {res.raw.channel_code}')

    def on_sysmontap_message(self, res):
        if isinstance(res.selector, list):
            if isinstance(res.selector, list):
                for data in res.selector:
                    # 従来互換のデータに変換する
                    if 'System' in data:
                        data['System'] = {'netBytesIn': data['System'][0], 'netBytesOut': data['System'][1]}
                    if 'Processes' in data:
                        processes = []
                        for id in data['Processes']:
                            x = data['Processes'][id]
                            processes.append([x[0], {'name': x[0], 'memResidentSize': x[1], 'cpuUsage': x[2], 'pid': x[3]}])
                        data['Processes'] = processes
            print(json.dumps(res.selector, indent=None))

    def setup_monitoring(self):
        self.rpc.register_undefined_callback(self.dropped_message)
        self.rpc.call('com.apple.instruments.server.services.sysmontap', 'setConfig:', {
            'ur': 1000,
            'bm': 0,
            'procAttrs': ['name', 'memResidentSize', 'cpuUsage', 'pid'],
            'sysAttrs': ['netBytesIn', 'netBytesOut'],
            'cpuUsage': True,
            'sampleInterval': 1000000000
        })
        self.rpc.register_channel_callback('com.apple.instruments.server.services.sysmontap', self.on_sysmontap_message)

    def start(self):
        response = self.rpc.call('com.apple.instruments.server.services.sysmontap', 'start').selector
        self.logger.info(f'start {response}')

    def stop(self):
        response = self.rpc.call('com.apple.instruments.server.services.sysmontap', 'stop').selector
        self.logger.info(f'stop {response}')


class IOSMonitor:
    API_URL = 'http://localhost:3333/sessions'
    RETRY_DELAY = 5
    MONITOR_INTERVAL = 5  # 1分ごとに接続を確認

    def __init__(self, udid):
        self.udid = udid
        self.rpc = None
        self.sysmontap = None
        self.lock = threading.Lock()
        self.logger = self.setup_logger()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logger(self):
        class StderrFilter(logging.Filter):
            def filter(self, record):
                return record.levelno >= logging.WARNING

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file_path = os.path.join(os.getcwd(), 'ios17_monitor.log')

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

    def signal_handler(self, sig, frame):
        self.logger.info('Received signal to stop. Exiting gracefully...')
        raise GracefulExit()

    def stop(self):
        with self.lock:
            if self.sysmontap:
                try:
                    self.logger.info('Starting cleanup sysmontap')
                    self.sysmontap.stop()
                except Exception as e:
                    self.logger.error(f'Error stopping sysmontap: {e}')

            if self.rpc:
                try:
                    self.logger.info('Starting cleanup rpc')
                    self.rpc.stop()
                except Exception as e:
                    self.logger.error(f'Error stopping RPC: {e}')
                finally:
                    self.rpc = None

    def get_connection_info(self):
        try:
            response = requests.get(self.API_URL, timeout=10)
            response.raise_for_status()
            sessions = response.json()
            self.logger.debug(f'Sessions: {sessions}')
            if self.udid in sessions:
                return sessions[self.udid]['host'], sessions[self.udid]['port']
            else:
                self.logger.warning(f'No session found for UDID: {self.udid}')
        except requests.RequestException as e:
            self.logger.error(f'Failed to connect to the API: {e}')
        except ValueError as e:
            self.logger.error(f'Failed to parse API response: {e}')
        return None, None

    def connect_and_monitor(self, host, port):
        self.logger.info(f'Attempting to connect to {host}:{port} for UDID: {self.udid}')

        with RemoteLockdownClient((host, port)) as rsd:
            self.logger.info('Successfully connected to RemoteLockdownClient')
            self.rpc = InstrumentServer(rsd).init()
            self.logger.info('InstrumentServer initialized')
            self.sysmontap = IOS17Sysmontap(self.rpc, self.logger)
            self.sysmontap.start()

    def run(self):
        self.logger.info(f'Starting iOS Device Monitoring Script for UDID: {self.udid}')
        try:
            host, port = self.get_connection_info()
            if host and port:
                self.connect_and_monitor(host, port)
                while True:
                    time.sleep(1)
        except GracefulExit:
            self.logger.info('Received exit signal, stopping monitoring.')
        finally:
            self.stop()
            self.logger.info('Monitoring stopped.')

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0


def main(udid):
    monitor = IOSMonitor(udid)
    error_count = 0
    while True:
        try:
            monitor.run()
            return
        except GracefulExit:
            return
        except Exception:
            error_count += 1
            monitor.logger.exception('Failed to connect pymobiledevice3.')
            if 10 < error_count:
                monitor.logger.error('Exceeded retries for restarting pymobiledevice3.')
                return

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 ios17_monitor.py <UDID>')
        sys.exit(1)

    udid = sys.argv[1]
    main(udid)

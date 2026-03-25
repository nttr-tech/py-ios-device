#!/bin/sh
set -e

# x86_64向けのビルド
# rtk13で確認

python_path=/usr/local/bin/python3

architectures=("x86_64")
for arch in "${architectures[@]}"; do
  arch -${arch} ${python_path} -m venv venv_${arch}
  source venv_${arch}/bin/activate

  arch -${arch} pip install --upgrade pip
  arch -${arch} pip install pyinstaller

  arch -${arch} pip install flask
  arch -${arch} pip install requests
  arch -${arch} pip install pyOpenSSL
  arch -${arch} pip install pyasn1
  arch -${arch} pip install construct
  arch -${arch} pip install hyperframe
  arch -${arch} pip install coloredlogs

  pyinstaller --onefile --name ios_tunnel_server \
  --distpath dist/${arch} \
  --hidden-import ios_device \
  --hidden-import flask \
  --hidden-import requests \
  --collect-all ios_device \
  --collect-all flask \
  --collect-all requests \
  ios_tunnel_server.py

  pyinstaller --onefile --name ios17_monitor \
  --distpath dist/${arch} \
  --hidden-import ios_device \
  --hidden-import requests \
  --hidden-import OpenSSL \
  --hidden-import pyasn1 \
  --hidden-import construct \
  --hidden-import hyperframe \
  --hidden-import coloredlogs \
  --collect-all ios_device \
  --collect-all requests \
  --collect-all OpenSSL \
  --collect-all pyasn1 \
  --collect-all construct \
  --collect-all hyperframe \
  --collect-all coloredlogs \
  ios17_monitor.py
done

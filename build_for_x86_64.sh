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

  pyinstaller --onefile --name ios_tunnel_server \
  --hidden-import ios_device \
  --hidden-import flask \
  --collect-all ios_device \
  --collect-all flask \
  ios_tunnel_server.py

  pyinstaller --onefile --name ios17_monitor \
  --hidden-import ios_device \
  --hidden-import requests \
  --hidden-import OpenSSL \
  --hidden-import pyasn1 \
  --collect-all ios_device \
  --collect-all requests \
  --collect-all OpenSSL \
  --collect-all pyasn1 \
  ios17_monitor.py
done

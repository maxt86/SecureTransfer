@echo off
title SecureTransfer Builder
color 02
python setup.py build_ext -i
move stenc.cp38-win_amd64.pyd pack
move stdec.cp38-win_amd64.pyd pack
move stkey.cp38-win_amd64.pyd pack
cd pack
pyarmor pack --clean -n SecureTransfer_Encrypt -x "--exact " -e "-Fw -i n.ico " _stenc.py
pyarmor pack --clean -n SecureTransfer_Decrypt -x "--exact " -e "-Fw -i n.ico " _stdec.py
pyarmor pack --clean -n SecureTransfer_Key     -x "--exact " -e "-F  -i n.ico " _stkey.py

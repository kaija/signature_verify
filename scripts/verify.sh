#!/bin/bash
openssl dgst -sha256 -verify pub.pem -signature demo.sha256 demo.luac

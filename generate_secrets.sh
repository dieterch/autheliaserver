#!/bin/bash
echo "JWT Secret:"
openssl rand -hex 64
echo
echo "Session Secret:"
openssl rand -hex 32
echo
echo "Storage Encryption Key:"
openssl rand -hex 32

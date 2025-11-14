hyperfine "./RSA -t openssl -n 1024 -m Hello\ world!" "./RSA -t optimized -n 1024 -m Hello\ world!" "./RSA -t naive -n 1024 -m Hello\ world!" -r 50

# RSA-large-prime-numbers

# 1. Build the Docker image using the Dockerfile.
for Windows Power Shell:

```

docker build -t rsa-project:latest .

docker run -it --name rsa_analysis_env rsa-project:latest

```

# 2. Get the permission to the compilation script.
(Inside Container / Bash)
```
chmod +x compile_efficient.sh
```
# 3. Compile the source code.
```
./compile_efficient.sh
```

# 4. Execute the Hyperfine benchmark test.
This runs RSA implementations (openssl, optimized, naive) 50 times (-r 50) to calculate mean time and standard deviation for performance analysis.
```
hyperfine "./RSA -t openssl -n 1024 -m Hello\ world!" \
          "./RSA -t optimized -n 1024 -m Hello\ world!" \
          "./RSA -t naive -n 1024 -m Hello\ world!" \
          -r 50
```
First version of code : https://github.com/mat-tador/RSA_with_large_primes

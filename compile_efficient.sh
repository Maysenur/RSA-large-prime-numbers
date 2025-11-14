g++ rsa_implementation.cpp \
    -I /root/cpp-libs/cxxopts/include \
    -lssl -lcrypto -lgmp -lgmpxx \
    -O3 -march=native -flto \
    -Wno-deprecated-declarations \
    -o RSA
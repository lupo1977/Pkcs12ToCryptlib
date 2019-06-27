# Pkcs12ToCryptlib
Transfers simple Pkcs12 certificates (with private keys) to the Pkcs15 format used in cryptlib.

```
Syntax: Pkcs12ToCryptlib <p12 filename> <p12 passwd> <p15 filename> <label> <passwd>
```

For example
```
Pkcs12ToCryptlib test.pfx test123 test.p15 test test123
```
Will create a cryptlib pkcs15 file named test.p15 out of test.pfx

Note:
The dlls and libs provided are based on cryptlib 3.4.2.
You should replace it accordingly.

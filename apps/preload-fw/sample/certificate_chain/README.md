# Certificate Chain Sample

The folder contains certificates and keys for reference.  

## Device ID Certificate Request
Sample Device ID certificate request(devid.req) is generated in first mutable code(mcuboot) and is signed by Device ID private key
Device ID private key is derived by CDI, in this sample, the value of CDI is all zero.  


## Root CA

```
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -subj "/C=TW/O=Aspeed/CN=Aspeed Root CA"
```

## Intermediate Certificate

```
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/C=TW/O=Aspeed/CN=Aspeed intermediate cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
```

## Leaf Certificate

```
openssl x509 -req -in devid.req -out leaf.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
```

devid.req is Device ID certificate signing request(DevID CSR), please refer to [Device ID Certificate Request](#device-id-certificate-request)

## Certificate chain

The following command generates sample certificate chain.

```
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in leaf.cert -out leaf.cert.der
cat ca.cert.der inter.cert.der leaf.cert.der > certchain.der
```

## Certificate Chain Update Flow 

Programmer should perform following actions in MP flow :  
1. Hold soc reset pin, pull high gpior6 then release soc reset pin, AST1060 will be in FWSPI programming mode.
2. Get DeviceID CSR from AST1060 internal flash offset 0x1c000

    ```
    struct {
        u32    magic;
        u32    length;
        u8     data[4096];
        u8     hash[32];
        u8     pubkey[97];
        u8     cert_type;
    } PFR_DEVID_CERT_INFO;
    ```

3. Get CSR from `data[4096]`
4. Send CSR to HSM to generate certificate chain(cerchain.der)
5. Receive certchain.der from HSM
6. Regenerate PFR_DEVID_CERT_INFO
   - put cerchain.der in data[4096]
   - update length to the length of certchain.der
   - set cert_type to 0.
7. Erase ast1060 internal flash offset 0x1c000 - 0x1dfff
8. Write PFR_DEVID_CERT_INFO to ast1060 flash offset 0x1c00 - 0x1dfff

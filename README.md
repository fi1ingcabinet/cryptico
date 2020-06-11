Used original cryptico to create a key, then implemented RFC2313 Encrypt and Decrypt functions as a test

Output of test_rsa2.html shows something like this:
```
RSA PEM keys:


Matt's passphrase: The Moon is a Harsh Mistress.

Bit length: 2048

Matt's public key string:

w5Sjr3UekqqLntnSQtJfx22YEP/DsYt3CFDUPgb9K/ITkte9PAh7DlaApVcOhsC11z1hNQJUBBBElGZA5QYwXamiVtZxPLdXI0dlLh15r4/2ynVN/vJhF9P9UgLxwkLCAQyxJ6Z5JlnrHByrLmdWGMS48nZSes7JoYK19qrYEjEik1SoCCXy8Lxm4P/r/IF9dklo63TkADIPvESrV2uLDeF8/+esboH5Oe4IUMuRwRVYWyhU+txbdhGZzqV+f6mLwnRw3uXprkd7pi3i4jXeh93StiK2Ppn4t/L0FfW55YA0p+kZNibHiDQYtmHBIpAFBxaz8E45yOcmmrpKnSlcKQ==

The above private key in PEM format is:

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAw5Sjr3UekqqLntnSQtJfx22YEP/DsYt3CFDUPgb9K/ITkte9
PAh7DlaApVcOhsC11z1hNQJUBBBElGZA5QYwXamiVtZxPLdXI0dlLh15r4/2ynVN
/vJhF9P9UgLxwkLCAQyxJ6Z5JlnrHByrLmdWGMS48nZSes7JoYK19qrYEjEik1So
CCXy8Lxm4P/r/IF9dklo63TkADIPvESrV2uLDeF8/+esboH5Oe4IUMuRwRVYWyhU
+txbdhGZzqV+f6mLwnRw3uXprkd7pi3i4jXeh93StiK2Ppn4t/L0FfW55YA0p+kZ
NibHiDQYtmHBIpAFBxaz8E45yOcmmrpKnSlcKQIBAwKCAQEAgmMXyk4UYccHvzvh
geGVL55lYKqCdlz6BYs4KVn+HUwNDI/TfVr8tDmrGOS0WdXOj35AzgGNWArYYu7V
7gQgPnEW5I72KHo6F4TuHr5RH7VPMaOJVKGWD+Ko4VdL1tcsALMgxRmmGZFHaBMc
yZo5Zdh7TE7hpzSGa6x5TxyQDB+V2vRQNZAMKYYbcdSyyMGrFjkoHZHlHWJkP9uT
dHRNPrBF6guSBRveMQC1TZJY/Z/tuy6SNZj5VkCUKb81V+0v/u07XLOAAXU7vPzu
pwUm9TV5nqgnoLa4FWSq87izeUjvKaE6hrAEWTdcu/8Z18MMvngNjUXbqCqx7JbG
/67TqwKBgQD3eQwDGcUfeoApfRv3V9TTK9VPbsAp5hT46X00ExpS2eztZXd9rw0o
60xgX5SdhhyIbfS/cVTnK22SPlMP6gOffLzgRdg4G9PX5JKUFIFGgPPY+f0sC84V
nZLoqNdhZmrHsHlVVH2SlcoUO2poHPfe8u8EN2/njdmP0lTcqJRKkQKBgQDKUdos
ngjBN/MUOSTod4opqR5dUFnibgmAcv4aFaLEVewmu17Tt8sDBSCX/NtuvojrVG26
OSH+SUMpUbOekcIkR1O3jgBxkEPKJh/o0yzdlxnDTilOwbnO+kkK/4lLSSgGOP3s
F6EubJb5YPiyQfOS9nObZPWIvs2L5YNDdQ7UGQKBgQCk+11XZoNqUarGU2f6Oo3i
HTjfnyrGmWNQm6jNYhGMkUieQ6T+dLNwnN2VlQ2+WWha8/h/oONEx55hfuIKnAJq
UyiVg+V6vTflQwxiuFYvAKKQpqjIB965E7dFxeTrmZyFIFDjjakMY9wNfPGavfqU
ofStekqaXpEKjDiTGw2HCwKBgIbhPB2+sIDP92LQw0WlBsZwvujgO+xJW6r3VBFj
wdg5SBnSPzfP3KyuFbqokknUW0eNnnwmFqmGLMY2d78L1sLaN8+0AEu1gobEFUXi
HekPZoI0G4nWe99RhgdVBjIwxVl7U/K6a3RIZKZApcwr97dO97zt+QXUiQfuV4JO
CeK7AoGAPh9dcu2KIBnntxNXAG1b5ikGa0FZR021u2PDImjnuLtCdJ0cmVxuuijf
76mGTfHlJHYeBFDZddo/gHsyXAeEBb30K95eX2Pzm7bHGiuJ+htfZnb1A4NHvtui
weZU/x9ZZUDhzgJbblrBGOHwM0S5k7Gz689m+EwY4aFifjhlVpU=
-----END RSA PRIVATE KEY-----

The above public key in PEM format is:

-----BEGIN RSA PRIVATE KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAw5Sjr3UekqqLntnSQtJf
x22YEP/DsYt3CFDUPgb9K/ITkte9PAh7DlaApVcOhsC11z1hNQJUBBBElGZA5QYw
XamiVtZxPLdXI0dlLh15r4/2ynVN/vJhF9P9UgLxwkLCAQyxJ6Z5JlnrHByrLmdW
GMS48nZSes7JoYK19qrYEjEik1SoCCXy8Lxm4P/r/IF9dklo63TkADIPvESrV2uL
DeF8/+esboH5Oe4IUMuRwRVYWyhU+txbdhGZzqV+f6mLwnRw3uXprkd7pi3i4jXe
h93StiK2Ppn4t/L0FfW55YA0p+kZNibHiDQYtmHBIpAFBxaz8E45yOcmmrpKnSlc
KQIBAw==
-----END RSA PRIVATE KEY-----

Encrypt some data with PKCS#1 v1.5 usnig cryptico:


Plaintext: 

Hi this is some text to encrypt!

Ciphertext: 

qE9TcLlThuY2KAgwaFcEFAoVz9vN49cRbFK7hXkLJbCztD39FTcbgYUCcCiVKhHZ
0bL+tXo8p+PCjgi5ns3a6O5LoyLhN/k5yFBHDUKdu/VDqEPj721KO6tTmX9u3nxz
/BE6Wd4/FdqNP+YoHgOdwIrMSNC9waeUeVTsvTD3EgygZyHyq2unvmOGjb8BwgKc
yjMApmR/QA449JUSX6ZmlVXHcwznnDKCxbryn8xvjDf0RlFjY2LcZIqX+uFhQJJI
B8xqbjwHpJXD4rMAFeKfxPE5ghpgd5QM2cTbuFXixnXnjIF2ATqQbW1FxxpAMmiM
/ZmsuNjW3a8cq3sSpKrL7g==


Decrypted text: 

Hi this is some text to encrypt!

Encrypt some data with PKCS#1 v1.5 from RFC 2313:


Plaintext: 

Hi this is some text to encrypt!

Ciphertext: 

U/hAz01Scg+YF+GHED0O+j4yo5YiXVohsXRE8a1Pk39zZzD3fi4QZwq9MWXNkGKd
SSM/bkAv5ku/G4ok0ZmLzUGkUtlpu+jRPI7cHc59GpUc2DaoJvhDbYKVPWgOJ3R3
6CiJc6m3A/5+4LQ4RWNmEEJ+9y80feLUotNt404NWLhv21iqXl26H5U7Q8OBGpXO
8ksf6GGou4vNsAI1/asBxiWbCJAPeNssxQzGrL6S+S5TH5m1zibh2ji2HKAQ0FYX
JEIubMzh4aBp/vpOjFyrtGUxcU5FO3jbaA5hbeICb4flf//48v4cdFkkxJE4EuD1
tfgu7SH+wJlC87pyIadzyg==


Decrypted Ciphertext: 

Hi this is some text to encrypt!

```

    
    
    

    
    



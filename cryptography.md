#Cryptography

## Tools Used
    - RapidTables
        - https://www.rapidtables.com/web/tools/index.html
            - Base64
            - Binary
            - Hex String
    - Cryptii
        - https://cryptii.com/
        - Decode
    - Decode
        - https://www.dcode.fr/
        - RSA Cipher
    - Kali Linux
        - Strings

##Challange 1
    Using rapidtables I was able to decode the encoded strings. The first string was a hexadecimal string. I ommited the 0x and pasted the remaining string into the deocoder.
    '0x73636f7270696f6e' 'scorpion'
    The decoded string is **scorpion**.

    I then proceeded to the next string. The string is a base64 string. I then pased that into the decoder. 
    'c2NyaWJibGU' 'scribble'
    The decoded string is **scribble**.

    The next string was a binary string. 
    '01110011 01100101 01100011 01110101 01110010 01100101 01101100 01111001' 'securely'
    The decoded string is **securely**.

    The last string was a double encoded string. Original word was first encoded into a base64 and then that base64 was encoded into a binary string. I first decoded the binary to reveal the base64 and then decoded the base64 to reveal the original string. 
    '01100010 01000111 00111001 01110011 01100010 01000111 01101100 01110111 01100010 00110011 01000001 00111101' 'bG9sbGlwb3A'
    'bG9sbGlwb3A' 'lollipop'
    The decoded string is **lollipop**.


## Challange 2
    Using crpytii I took the encrpyred string and decoded it using a ceaser cipher with a shift of 13. I used the Large Language Model Gemma to aid in my decription. The model was able to tell me the most logical cipher based on the encoding.
    'iveghny ynxr' 'virtual lake'
    The decoded string is **virtual lake**.

## Challange 3
    Using cryptii and gima I was able to determine that the cipher is a alphabetical substituion using the alphabet in reverse. 
    'hzuvob lyerlfh xzev' 'safely obvious cave'
    The decoded string is **safely obvious cave**.
Challange 3: cryptii.com
hzuvob lyerlfh xzev | Alphabetical Subsitution Cipher (Reverse Aphabet) | safely obvious cave

## Challange 4
    Based on the ... and the -- I was able to determine this was morse code. I used crpytii to convert the string. 
   '.... . / ... . -.-. .-. . - / --- ..-. / --. . - - .. -. --. / .- .... . .- -.. / .. ... / --. . - - .. -. --. / ... - .- .-. - . -.. / ... -.- -.-- / -.. -.- ...- -... / ----. ---.. .---- -....'  'the secret of getting ahead is getting started sky dkvb 9816'
   The decoded string is **the secret of getting ahead is getter strated sky dkvb 9816**.

Challange 5: cryptii.com
Handwrittten Notes 3 & 5

Cair eruSA-0org sgaeudrpesr K-II98.ue cn seYQ3 | Rail Cipher 3 | Courage is grace under pressure SKY-AIQI-9380.

F daS-eefn  n KZ3eheadty.YI8lta oiwy-Q0. r aI2 | Rail Cipher 5 | Feel the fear and do it anyway. SKY-IQIZ-3802.

Challange 6: cryptii.com
keyword: qizkwcgqbs
Y ln xkv lubj swlzqvkht, A vmzb pjk bbua we ddgs ILQ-GQYU-8026 | vigenere cipher | I do not fear computers, I fear the lack of them SKY-QIZK-8026

Challange 7: Kali
Strigns
strings Step1.jpg | grep SKY
SKY-TVJI-2063

Challage 8: dcode.fr
n = 1079
c = 996 894 379 631 894 82 379 852 631 677 677 194 893
p = 13
q = 83
SKY-KRYG-5530
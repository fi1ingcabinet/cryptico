// Encrypt/decrupt one single block using RSA as in rfc 2313

// §8 Encryption

/* There are 4 steps:

    1. encryption-block formatting,
    2. octet-string-to-integer conversion, 
    3. RSA computation,
    4. integer-to-octet-string conversion
*/


// §8.1 encryption block formatting 

// Create a class for the block to encrypt
//TODO:- Put some checks in the class to error if they dont add to right length etc.
function EncBlock(PS, data) {
        this.octet1 = "00";
        this.BT = "02";
        this.PS = PS;
        this.octetm1 = "00";
        this.data = data;
}


// Create an encryption block
function CreateEnccryptionBlock(plaintext,k) {
    
    //k = 128; // we are encrypting single block with key size 1024 so k=128 (8*128 = 1024)
    //k = k/8;
    data_16 = ascii_to_hexa(plaintext); // convert the plaintext to hex 
    
    //if ((data_16.length/2) >)
    
    length_data = (data_16.length)/2; 
    padding_length = k-length_data-3;
    //console.log(padding_length);
    padding_string = "";
    for (i = 0; i < padding_length; i++) {
        padding_string = padding_string + "12";
    } 
    //console.log(padding_string);
    
    newEncryptionBlock = new EncBlock(padding_string, data_16);
    //console.log(newEncryptionBlock);
    return newEncryptionBlock;
    
}

// §8.2 octet-string-to-integer conversion. Convert encryption block to a large number
function calculate_x(anyEncryptionBlock,k) {
    
    whole_string = anyEncryptionBlock.octet1 + newEncryptionBlock.BT + newEncryptionBlock.PS + newEncryptionBlock.octetm1 + newEncryptionBlock.data;
    //console.log(whole_string);
    //console.log(whole_string.length);

    x = bigInt(0);
    //console.log(x);
    for (i = 1; i <= k; i++){
        eb = whole_string.substring(2*(i-1), 2*(i));
        //console.log(eb);
        ebn = bigInt(parseInt(whole_string.substring(2*(i-1), 2*(i)),16));
        //console.log(ebn);
        
        //console.log("power of 2: ");
        pow_of_2 = bigInt(2).pow(8*(k-i));
        x = x.add(pow_of_2.multiply(ebn));
        //x = x.add(((2).pow(8*(1024-i))).multiply(ebn));
        //console.log(x,i);
        
    }
    
    return x;
}


// §8.3 RSA computation
function RSAcomputation(x, n, c) {
    
    y = bigInt(x,10).modPow(c,bigInt(n,10));
    
    //console.log(y);
    
    return y.toString();
}


// §8.4 Octet to string conversion. Create the ciphertext as decimal
function OctetToStringConversion16(y) {
    
    z = bigInt(y,10).toString(16);
    return z;
    
}


function Encrypt_function(plaintext, RSA_Key) {
    
    // §8.1
    k = RSA_Key.n.toString(16).length/2;
    console.log(k);
    plain_block = CreateEnccryptionBlock(plaintext,k);
    //§8.2
    x = calculate_x(plain_block,k);
    // §8.3
    n = bigInt(RSA_Key.n.toString(16),16);
    c = bigInt(RSA_Key.e.toString(16),16);
    y = RSAcomputation(x, n, c);
    // §8.4
    z = bigInt(y,10).toString(16);
    return z;
    
}


// §9 Decryption
/* there are 4 steps:

    1. octet-string-to-integer conversion, 
    2. RSA computation, 
    3. integer-to-octet-string conversion, 
    4. encryption-block parsing
*/

// §9.1 

function OctetToStringConversion10(y) {
    
    z = bigInt(y,16).toString(10);
    return z;
    
}

// §9.2 - RSA Computation

function RSAcomputationD(y,d,n) {
    
    x = bigInt(y,10).modPow(d,bigInt(n,10));
    
    return x.toString();
    
}


// §9.3 - Octet to string conversion. Create the ciphertext as decimal
//same as above §8.4

// §9.4 - parse
function ParseDecr(string){
    
    ct = string.split('00')[1];
    ct = hex2a(ct);
    console.log(ct);
    return ct;
    
}

function Decrypt_function(ctext, RSA_Key){
    
    // §9.1
    console.log(ctext);
    big_num = OctetToStringConversion10(ctext);
    // §9.2
    d = bigInt(RSA_Key.d.toString(16),16);
    n = bigInt(RSA_Key.n.toString(16),16);
    console.log(big_num);
    //console.log()
    x = RSAcomputationD(big_num,d,n);
    console.log(x);
    // §9.3
    s = OctetToStringConversion16(x);
    console.log(s);
    // §9.4
    pt = ParseDecr(s);
    
    return pt;
    
    
}





// Utility functions

//https://www.w3resource.com/javascript-exercises/javascript-string-exercise-27.php
function ascii_to_hexa(str)
  {
	var arr1 = [];
	for (var n = 0, l = str.length; n < l; n ++) 
     {
		var hex = Number(str.charCodeAt(n)).toString(16);
		arr1.push(hex);
	 }
	return arr1.join('');
   }
//https://stackoverflow.com/questions/3745666/how-to-convert-from-hex-to-ascii-in-javascript/36928422
function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; (i < hex.length && hex.substr(i, 2) !== '00'); i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}


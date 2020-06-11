// fi1ingcabinet added code to parse RSA cert, and encrypt/decrypt based on https://tools.ietf.org/html/rfc2313



//
// Return RSA public and private key in PEM format. Added by fi1ingcabinet
//
function RSAKeyOut(RSAKey){
    
    //
    //VERSION
    //
    //02=INTEGER, 01=length is 1 byte, 00 is the version
    version = "020100"
    
    //
    //n
    //
    n = RSAKey.n.toString(16);
    //add a pad if the first bit is a 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(n.charAt(0)) >= 0) {
        n2 = "00" +n;
        }
    else {
        n2=n;
    }
    n3 = (n2.length)/2;
    //construct prefix for n
    prefix_n = prefix_int(n3);
    //construct prefix + n
    n_final = prefix_n + n2;
    console.log(n_final);
    
    //
    //e
    //
    e = RSAKey.e.toString(16);
    //pad if single value
    if (e.length % 2 == 1){
            e = "0"+e;
        }
    e2 = (e.length)/2;
    //construct prefix for p
    prefix_e = prefix_int(e2);
    //construct prefix + e
    e_final = prefix_e + e;
    
    //
    //d
    //
    d = RSAKey.d.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(d.charAt(0)) >= 0) {
        d2 = "00" +d;
        }
    else {
        d2=d;
    }
    d3 = (d2.length)/2;
    //construct prefix for p
    prefix_d = prefix_int(d3);
    //construct prefix + d
    d_final = prefix_d + d2;
    
    //
    //p
    //
    p = RSAKey.p.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(p.charAt(0)) >= 0) {
        p2 = "00" +p;
        }
    else {
        p2=p;
    }
    p3 = (p2.length)/2;
    //construct prefix for p
    prefix_p = prefix_int(p3);
    //construct prefix + p
    p_final = prefix_p + p2;
    
    //
    //q
    //
    q = RSAKey.q.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(q.charAt(0)) >= 0) {
        q2 = "00" +q;
        }
    else {
        q2=q;
    }
    q3 = (q2.length)/2;
    //construct prefix for q
    prefix_q = prefix_int(q3);
    //construct prefix + q
    q_final = prefix_q + q2;
    
    //
    //dmp1
    //
    dmp1 = RSAKey.dmp1.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(dmp1.charAt(0)) >= 0) {
        dmp12 = "00" +dmp1;
        }
    else {
        dmp12=dmp1;
    }
    dmp13 = (dmp12.length)/2;
    //construct prefix for dmp1
    prefix_dmp1 = prefix_int(dmp13);
    //construct prefix + dmp1
    dmp1_final = prefix_dmp1 + dmp12;
    
    //
    //dmq1
    //
    dmq1 = RSAKey.dmq1.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(dmq1.charAt(0)) >= 0) {
        dmq12 = "00" +dmq1;
        }
    else {
        dmq12=dmq1;
    }
    dmq13 = (dmq1.length)/2;
    //construct prefix for dmq1
    prefix_dmq1 = prefix_int(dmq13);
    //construct prefix + dmq1
    dmq1_final = prefix_dmq1 + dmq1;    
    
    //
    //coeff
    //
    coeff = RSAKey.coeff.toString(16);
    //pad if single value
    if (coeff.length % 2 == 1){
            coeff = "0"+coeff;
        }
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(coeff.charAt(0)) >= 0) {
        coeff2 = "00" +coeff;
        }
    else {
        coeff2=coeff;
    }
    coeff3 = (coeff2.length)/2;
    //construct prefix for coeff
    prefix_coeff = prefix_int(coeff3);
    //construct prefix + coeff
    coeff_final = prefix_coeff + coeff2;
    
    //
    //get the private key
    //
    private_key=""

    //total header
    head_1 = "30";
    total_content = version + n_final + e_final + d_final + p_final + q_final + dmp1_final + dmq1_final + coeff_final;
    total_length = (total_content.length)/2;
    total_length_byte = prefix_int(total_length).substring(2,);
    total_head = head_1 + total_length_byte;
    private_key = total_head + total_content;
    
    
    //
    //get the public key
    //
    public_key=""
    //total header
    head_1 = "30";
    total_content = n_final + e_final;
    total_length = (total_content.length)/2;
    total_length_byte = prefix_int(total_length).substring(2,);
    total_head = head_1 + total_length_byte;
    public_key_1 = total_head + total_content;
    head_2 = "00" + public_key_1;
    head_2_length = (head_2.length)/2;
    head_3 = "03" + prefix_int(head_2_length).substring(2,) + head_2;
    head_4 = "300d06092a864886f70d0101010500" + head_3;    
    head_4_length = (head_4.length)/2;
    head_5 = "30" + prefix_int(head_4_length).substring(2,) + head_4;
    public_key = head_5;
       
    return {private_key, public_key};

}


// function to add ASN.1 prefixes - fi1ingcabinet
function prefix_int(k){
    //if length of contents is < 127 the second byte is the length
    if (k<127){
        length_byte = k.toString(16)
        //if it is only one character (i.e. 1-16 in decimal) long, it requires a pad
        if (length_byte.length % 2 == 1){
            length_byte = "0"+length_byte;
        }
        //add the INTEGER prefix
        prefix = "02" + length_byte;
        return prefix
    }
    if (127 < k ){
        //work out how many bytes we need to use
        if ( (k/256)>=1 ){
            num_bytes = 2;
        }
        else {
            num_bytes = 1;
        }
        //length_byte is the length byte encoded
        len = 128 + num_bytes;
        length_byte = len.toString(16);
        //encode the value of the length
        hex_bytes = k.toString(16);        
        if (hex_bytes.length % 2 == 1){
            hex_bytes = "0"+hex_bytes;
        }
        //add the INTEGER prefix
        prefix = "02" + length_byte + hex_bytes;        
        return prefix;
    }
}

// function to split every 64 characters for log added by fi1ingcabinet from https://stackoverflow.com/questions/4321500/how-to-insert-a-newline-character-after-every-200-characters-with-jquery
function split64(str) {
  var result = '';
  while (str.length > 0) {
    result += str.substring(0, 64) + '\n';
    str = str.substring(64);
  }
  return result;
}

// function to split every 64 characters for HTML added by fi1ingcabinet from https://stackoverflow.com/questions/4321500/how-to-insert-a-newline-character-after-every-200-characters-with-jquery
function split64_html(str) {
  var result = '';
  while (str.length > 0) {
    result += str.substring(0, 64) + '<br>';
    str = str.substring(64);
  }
  return result;
}

// Function to add prefix and endfix in log added by fi1ingcabinet
function add_pem(str){
    
    pem_key = "-----BEGIN RSA PRIVATE KEY-----" + "\n" + str + "-----END RSA PRIVATE KEY-----";
    
    return pem_key;
}

// Function to add prefix and endfix in HTML added by fi1ingcabinet
function add_pem_html(str){
    
    pem_key = "-----BEGIN RSA PRIVATE KEY-----" + "<br>" + str + "-----END RSA PRIVATE KEY-----";
    
    return pem_key;
}

// copied from elsewhere 
function base16tobase64(h) {
    var i;
    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var c;
    var ret = "";
    if(h.length % 2 == 1)
    {
        h = "0" + h;
    }
    for (i = 0; i + 3 <= h.length; i += 3)
    {
        c = parseInt(h.substring(i, i + 3), 16);
        ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63);
    }
    if (i + 1 == h.length)
    {
        c = parseInt(h.substring(i, i + 1), 16);
        ret += base64Chars.charAt(c << 2);
    }
    else if (i + 2 == h.length)
    {
        c = parseInt(h.substring(i, i + 2), 16);
        ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4);
    }
    while ((ret.length & 3) > 0) ret += "=";
    return ret;
}



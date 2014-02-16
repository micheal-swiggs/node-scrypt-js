QUnit.log(function (details){
    if (details.result == true) return;
    console.log("FAILED");
    console.log("message:  "+details.message);
    console.log("expected: "+details.expected);
    console.log("actual:   "+details.actual);
});

test("scrypt tests", function (){
    var Utf8 = CryptoJS.enc.Utf8;

	var t1=new Date();
    var password = Utf8.parse("password");
    var salt = Utf8.parse("NaCl");
    var N = 1024;
    var r = 8;
    var p = 16;
    var dkLen = 64;
    var expected = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
    var actual = scrypt(password, salt, N, r, p, dkLen/4);
    equal(actual, expected, "scrypt-test 1");
	console.log('Scrypt: '+(new Date()-t1)+' ms');

    t1 = new Date();
    password = Utf8.parse("pleaseletmein");
    salt = Utf8.parse("SodiumChloride");
    N = 16384;
    r = 8;
    p = 1;
    dkLen = 64;
    expected = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887";
    actual = scrypt(password, salt, N, r, p, dkLen/4);
    equal (actual, expected, "scrypt-test 2");
    console.log('Scrypt: '+(new Date()-t1)+" ms");
    return;
    t1 = new Date();
    password = Utf8.parse("pleaseletmein");
    salt = Utf8.parse("SodiumChloride");
    N = 1048576;
    r = 8;
    p = 1;
    dkLen = 64;
    expected = "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4";
    actual = scrypt(password, salt, N, r, p, dkLen/4);
    equal (actual, expected, "scrypt-test 3");
    console.log('Scrypt: '+(new Date()-t1)+" ms");


});

test("pbkdf2_hmac_sha1_long", function(){
    return;
    var password, salt, c, dkLen, expected;
    var Utf8 = CryptoJS.enc.Utf8;

    password = Utf8.parse('password');
    salt = Utf8.parse('salt');
    c = 16777216;
    dkLen = 20;
    expected = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-4" );
});

test("pbkdf2_hmac_sha1_rfc6070", function (){
    var password, salt, c, dkLen, expected;
    var Utf8 = CryptoJS.enc.Utf8;

    password = Utf8.parse("password");
    salt = Utf8.parse("salt");
    c = 1;
    dkLen = 20;
    expected = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-1" );

    password = Utf8.parse('password');
    salt = Utf8.parse('salt');
    c = 2;
    dkLen = 20;
    expected = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-2" );

    password = Utf8.parse('password');
    salt = Utf8.parse('salt');
    c = 4096;
    dkLen = 20;
    expected = "4b007901b765489abead49d926f721d065a429c1";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-3" );

    password = Utf8.parse('passwordPASSWORDpassword');
    salt = Utf8.parse('saltSALTsaltSALTsaltSALTsaltSALTsalt');
    c = 4096;
    dkLen = 25;
    expected = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-5" );

    password = Utf8.parse('pass\0word');
    salt = Utf8.parse('sa\0lt');
    c = 4096;
    dkLen = 16;
    expected = "56fa6aa75548099dcc37d7f03425e0c3";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-6" );

    password = Utf8.parse('password');
    salt = Utf8.parse('ATHENA.MIT.EDUraeburn');
    c = 1;
    dkLen = 16;
    expected = "cdedb5281bb2f801565a1122b2563515";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-7" );

    dkLen = 32;
    expected = "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-8" );

    password = Utf8.parse('password');
    salt = Utf8.parse('ATHENA.MIT.EDUraeburn');
    c = 2;
    dkLen = 16;
    expected = "01dbee7f4a9e243e988b62c73cda935d";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-9" );

    dkLen = 32;
    expected = "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-10" );

    password = Utf8.parse('password');
    salt = Utf8.parse('ATHENA.MIT.EDUraeburn');
    c = 1200;
    dkLen = 16;
    expected = "5c08eb61fdf71e4e4ec3cf6ba1f5512b";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-11" );

    dkLen = 32;
    expected = "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13";
    actual = CryptoJS.PBKDF2(password, salt, { iterations: c, keySize: dkLen/4});
    equal( actual, expected, "pbkdf2-12" );

});

test("pbkdf2_hmac_sha2", function (){
    var Utf8 = CryptoJS.enc.Utf8;

    var password = Utf8.parse("password");
    var salt = Utf8.parse("salt");
    var c = 4096;
    var dkLen = 32;
    var actual = CryptoJS.PBKDF2(password, salt,
            { iterations: c, keySize: dkLen/4, hasher: CryptoJS.algo.SHA256});
    var expected = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a";
    equal (actual, expected, "pbkdf2-sha256");
});


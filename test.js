var modes = require('./modes');
var cipher = require('./');
var crypto = require('crypto');
var password = new Buffer('calvinball');
var test = require('tape');
var algo = 'aes128';
function ourTest(algo) {
  test(algo, function (t) {
    t.plan(1);
    var enc = new cipher.Cipher(algo, password);
    var dec = new cipher.Decipher(algo, password);
    var text = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
    out = '';
    enc.pipe(dec).on('data', function (d){
      out += d.toString();
    }).on('finish', function () {
      t.equals(text, out);
    });
    enc.write(text);
    enc.end();
  });
}
Object.keys(modes).forEach(ourTest);

function ourTest2(algo) {
  var rando = crypto.randomBytes(2);
  while(!rando[1]) {
    rando = crypto.randomBytes(2);
  }
  test(algo + ' iterations: ' + rando[0] + ' salt length: ' + rando[1], function (t) {
    t.plan(2);
    
    var enc = new cipher.Cipher(algo, password, rando[0], rando[1]);
    var dec = new cipher.Decipher(algo, password);
    var text = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
    var len = 0;
    out = '';
    enc.on('data', function (d) {
      len += d.length;
    }).on('end', function () {
      var outlen = (new Buffer(text)).length;
      var padding = modes[algo].padding !== false ? 16 - (outlen % 16) : 0;
      var headers = rando[1] + 8;
      var finLen = outlen + padding + headers;
      t.equals(len, finLen, 'enc length');
    }).pipe(dec).on('data', function (d){
      out += d.toString();
    }).on('end', function () {
      t.equals(text, out, 'texts');
    });
    
    enc.write(text);
    enc.end();
  });
}
Object.keys(modes).forEach(ourTest2);
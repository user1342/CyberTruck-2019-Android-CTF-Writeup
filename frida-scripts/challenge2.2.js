function Main() {

    function s(x) {return x.charCodeAt(0);}

    // setting the seed to be the same value hardcoded in the application. Then converts to bytearray.
    var value = "uncr4ck4ble_k3yle$$".split('').map(s);
    var buffer1 = Java.array('byte', value);

    // value in the assets folder file 'd474_47_r357_mu57_pR073C73D700!!'
    var value = "d474_47_r357_mu57_pR073C73D700!!".split('').map(s);
    var buffer2 = Java.array('byte', value);
    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();


    // Runs the 'generateDynamicKey' method of 'Challenge1' with the bytearray
    Java.perform(function () {
      var challenge1Class = Java.use("org.nowsecure.cybertruck.keygenerators.a");
      var initialisedChallenge1Class = challenge1Class.$new(context);
      var dynamicKey = initialisedChallenge1Class.a(buffer1, buffer2);

      // Logs the output
      console.log(ba2hex(dynamicKey));
    });

}

// Byte array to hex code supplied by challenge.
function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toLowerCase();
}

// Perform main function
Java.perform(Main);

function Main() {

    function s(x) {return x.charCodeAt(0);}

    // setting the seed to be the same value hardcoded in the application. Then converts to bytearray.
    var value = "CyB3r_tRucK_Ch4113ng3".split('').map(s);
    var buffer = Java.array('byte', value);

    // Runs the 'generateDynamicKey' method of 'Challenge1' with the bytearray
    Java.perform(function () {
      var challenge1Class = Java.use("org.nowsecure.cybertruck.keygenerators.Challenge1");
      var initialisedChallenge1Class = challenge1Class.$new();
      var dynamicKey = initialisedChallenge1Class.generateDynamicKey(buffer);

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

# Cyber Truck 2019 Writeup 🚗

This is a writeup for the [Now Secure](https://www.nowsecure.com/) Android reverse engineering CTF based on analyzing a car keyless application.

... It has nothing to do with the Tesla CyberTruck.

<p align="center">
    <img width=100% src="https://media1.giphy.com/media/QWjyvdpMDYKbOFLdIv/giphy.gif?cid=ecf05e4789df802731724ceecdf469de65daf24b4de39c43&rid=giphy.gif">
  </a>
</p>

<br>
<img align="right" width="200" src="/images/application.png">

You can find the CTF, and all resources for it, on [GitHub](https://github.com/nowsecure/cybertruckchallenge19). Only continue if you're not interested in completing the CTF yourself and you want to hear me talk about some cool techniques.

In addition to this writeup there is another great writeup by [Joan Calabrés](https://www.verso.re/posts/cybertruck/).

The application is fairly simple with only one activity, a button, and two toggle switches.

## Used FOSS Tools
The following walktrhough uses the below tools:
- [Jadx-Gui](https://github.com/skylot/jadx) - For analyzing decompiled Java.
- [Frida](https://github.com/frida/frida/releases) - For hooking the Android application.
- [APKTool](https://ibotpeaches.github.io/Apktool/) - For getting access to the Native library used by the application. You can also just unzip the APK.
- [Ghidra](https://ghidra-sre.org/) - Used for reversing the Native library.

## Tips

### ARM64
In this walkthrough i'm using a rooted Pixel2 running ARM64.

### Running Frida Scripts
None of the Frida scripts we use today are going to be overly complicated so when writing them save them to a Javascript ```.js``` file and run them with the Frida command ```frida -U "org.nowsecure.cybertruck" -l .\script.js --no-pause```.

### Converting byte arrays to hex
In Challenge 1.2 an 2.2 this tutorial uses a Javascript function called ```ba2hex```. This was supplied by the CTF orgniser and simplifies converting byte arrays to hex.

```javascript
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
```

## Challenge 1.1
**Challenge:** *Static Analysis*: "There is a secret used to create a DES key. Can you tell me which one?"

Opening the application in Jadx-Gui we can start reviewing the decompiled java. As there is a class called ```Challenge1.java``` lets start there. After reviewing this class we can see that the main code block that uses [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) is the ```generateDynamicKey``` method, where it's using the [DES key spec](https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/DESKeySpec.html).

In this method we can also see the byte array which is used for padding. This byte array is our flag.

```java
public byte[] generateDynamicKey(byte[] bArr) {
    SecretKey generateSecret = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec("s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!".getBytes()));
    Cipher instance = Cipher.getInstance("DES");
    instance.init(1, generateSecret);
    return instance.doFinal(bArr);
}
```

**FLAG**: ```s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!```

## Challenge 1.2
**Challenge**: *Dynamic Analysis*: "There is a token generated at runtime to unlock the carid=1. Can you get it? (flag must be summitted in hex all lowercase)"

Returning to the method in challenge 1.1 we can see that it generates a DES key at runtime. As we have the bytearray that is hardcoded as input to this method we could reprdocue the code in Java to return the key, however, we can also do this using Frida.

Below we use the padding we found in the previous section to make a byte array which is passed to the ```generateDynamicKey``` method.

```javascript
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
```

**FLAG**: ```046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6```

## Challenge 2.1:
**Challenge**: *Static Analysis*: This challenge has been obfuscated with ProGuard, therefore you will not recover the AES key.

In Android the most commonly used tool for obfuscating code is a tool called ProGuard. ProGuard has a handful of key areas of functionality, these being:

- Shrinking: The shrinking step detects and removes unused classes, fields, methods, and attributes.
- Optimizer: The optimization step analyzes and optimizes the bytecode of the methods.
- Obfusator: The obfuscation step renames the remaining classes, fields, and methods using short meaningless names.
- Preverifier: The final preverification step adds preverification information to the classes, which is required for Java Micro Edition and for Java 6 and higher.

The main area that effects us today is ProGuards obfuscation which has renamed the classes, methods, and resources used in Challenge 2.

Staying in the sub-package, ```keygenerators```, as of challenge 1 we can see another class called ```a.java```. It looks like this class has been obfuscated by ProGuard so is probably a good place to look.  

In this class one of the main pieces that is instantly suspicious is the line ```inputStream = context.getAssets().open("ch2.key");```. This line is loading a file from the assets folder and is using that in using the loaded stream later on in the program. The Assets folder in Android is used by Application developers to store arbitrary storage (Including: JSON, images, executables, keys, etc).

After finding the applications ```assets``` folder we find the FLAG for this challenge.

**FLAG**: ```d474_47_r357_mu57_pR073C73D700!!```

# Challenge 2.2
**Challenge**: *Static Analysis*: There is a token generated at runtime to unlock the carid=2. Can you get it? (flag must be summitted in hex all lowercase).

Remaining in ```a.java``` we can see a very similar method to the method used to generate the dynamic key in challenge 1.2. This time this method has been obfuscated and is also called ```a```.

We can retrieve the key in a very similar manner to Challenge 1.2, however, with two main differences. In this challenge the class we are initialising takes a Context in it's construction, as we can see from ```public a(Context context) {```. The second change is that the method takes two byte arrays instead of one. The former of these problems can be fixed with creating a context variable in the Javascript with ```    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();```. The latter can also be fixed by knowing what these byte arrays shuld be.

```java
public byte[] a(byte[] bArr, byte[] bArr2) {
    SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, "AES");
    Cipher instance = Cipher.getInstance("AES/ECB/PKCS7Padding");
    instance.init(1, secretKeySpec);
    return instance.doFinal(bArr);
}
```

After setting the two values from the assets file and the value hardcoded into the program as well as the application context we can use very similar code to Challenge 1.2.

```javascript
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
```

**FLAG**: ```512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16```

## Challenge 3.1
**Challenge**: *Static Analysis*: There is an interesting string in the native code. Can you catch it?

This challenge involves reversing the Native library used by the CyberTruck application. To do this we'll need to either unzip the .apk file or use APKTool. This can be done with ```apktool d cybertruck19.apk```. We can then identify the library, which will be named ```libnative-lib.so```. The library you use will depend on the type of device you're using (run ```adb shell uname -a``` to check). As i'm using a ARM 64 device I'll be using the ```arm64-v8a``` library. We can confirm that ```libnative-lib.so``` is the library we're looking for as it's directly loaded in the ```MainActivity.java``` of the application:

 ```java
 System.loadLibrary("native-lib");
 ```

We then need to load the native library into [Ghidra](https://ghidra-sre.org/CheatSheet.html) and use it's string search function. After reviewing the strings returned we can find the one that stands out the most.

<br>
<p align="center">
  <img src="/images/challenge3.1-strings.png" width="400" />
  <br>
  <br>
  Ghidra string search
</p>
<br>

**FLAG**: ```Native_c0d3_1s_h4rd3r_To_r3vers3```

## Challenge 3.2
**Challenge**: *Dynamic Analysis*: Get the secret generated at runtime to unlock the carid=3. Security by obscurity is not a great design. Use real crypto! (hint: check the length when summitting the secret!)

In this challenge we first need to locate the ```Java_org_nowsecure_cybertruck_MainActivity_init``` method in the native library in Ghidra. I did this by searching for the ```"KEYLESS CRYPTO [3] - Unlocking carID = 3"``` string.

In Ghidra using both the **Decompiled** view and the **Function Graph** view will help us in reversing this code. After viewing the ```Java_org_nowsecure_cybertruck_MainActivity_init``` function in either of these views we can see that we have a while look doing a heap of logic on several of the registers. The main part of this is where we can see the ARM instruction ```eor w10 ,w10 ,w11```. This XORs the values in the general purpose registers 10 and 11 and stores their XORd result in register 10. We want to get access to the XORd value of these registers.

To do this we're going to use the Frida ```Interceptor.attach```. Unlike when we've used ```Java.use``` in this past the code inside of our [interceptor](https://frida.re/docs/javascript-api/#interceptor) will only be called when that section of the native code is run. For us this will be when the "Unlock" button is selected.

To do this we first need to identify the relative offset of the ```eor``` instruction.

<br>
<p align="center">
  <img src="/images/challenge3.2-graph.png" width="300" />
  <img src="/images/challenge3.2-xor.png" width="300" />
  <br>
  <br>
  Graph view and Assembly view of the eor instruction
</p>
<br>

After we have the relative offset we can add that to our modules base address and intercept the call. After this point we only need to [XOR](https://stackoverflow.com/questions/14526584/what-does-the-xor-operator-do#:~:text=XOR%20is%20a%20binary%20operation,corresponding%20bits%20of%20a%20number) the values in the general purpose registers 10 and 11 and we have our FLAG.

```javascript
// Gets XOR location relative offset.
const exor = 0x7cc;
Interceptor.attach(module.base.add(exor), function () {

  // Shows registers
  //console.log(JSON.stringify(this.context));
  var x = this.context.x10;
  var y = this.context.x11;
  var z = x ^ y;

  secret+=String.fromCharCode(z)
  console.log("\n"+secret)
});
```

**FLAG:** ```backd00r$Mu$tAlw4ysBeF0rb1dd3n$$```

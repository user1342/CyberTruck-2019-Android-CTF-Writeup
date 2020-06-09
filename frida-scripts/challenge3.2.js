Process.enumerateModules({
  onMatch: function(module){
    //console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
    if (module.name=="libnative-lib.so"){
      console.log(module.name)
      var secret=""

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


    }
  },
  onComplete: function(){}
});

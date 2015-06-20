var utils = require('./utils');
var stream = require('stream');
var util = require('util');
var net = require('net');

function PacketStream (opts) {
  var self = this;

  stream.Transform.call(self);
  self._readableState.objectMode = true;

  // Propagate pressure properly, and don't parse way too much
  self._readableState.highWaterMark = 1;

  self.option_handlers = opts.option_handlers || [];

  self.decode_handler = create_options_decode_handler(self.option_handlers);
  self.encode_handler = create_options_encode_handler(self.option_handlers);

  return self;
};
util.inherits(PacketStream, stream.Transform);

PacketStream.prototype._transform = function transform(data, encoding, callback) { 
  var self = this;

  var is_dhcp = false;
  // We're only dealing with UDP here, so we know that we have the entire
  // message in the data. No need to buffer up until length.
  var pkt = new Packet(data, { decode_handler: self.decode_handler, encode_handler: self.encode_handler });
  self.push(pkt);

  // XXX: we're to call the callback with an error, but for now, lets assume everything is fine
  callback(null);
};

{
  option_no: 1,
  encode: function() { },
  decode: function() { },
  matcher: function() { } || null,
  priority: 1
}

function create_options_decode_handler (array) {

  // It turns out that DHCP requires some specific ordering of options,
  // so here we sort roughly using a "priority" field.
  var sorted_by_priority = array.sort(function(a, b) {
    if(a.priority > b.priority) return 1;
    if(a.priority < b.priority) return -1;
    return 0;
  });

  return function options_handler (buffer) {
    var ret = {};
    sorted_by_priority.forEach(function(obj) {
      var _ref = [0, buffer.slice(240)]; var i = _ref[0]; options = _ref[1];
      while (i < options.length && options[i] !== 255) {
        optNum = options[i++];
        optLen = options[i++];

        optOrigVal = options.slice(i, i + optLen);

        // Avoid extra work
        if(optNum == obj.option_no) {
          // We may have an option handler that only works if the value matches something
          // eg: vendor id ipxe will mean that there's extra info
          if(obj.matcher === null || obj.matcher === undefined || obj.matcher(optOrigVal)){
            // Since some handlers might want to create or remove several entries in the
            // return value, we pass the return value in so that it can add/remove stuff
            obj.decode(optOrigVal, ret);
          }
        }
      }
    });

    return ret;
  };
}

function Packet(data, options) {
  var self = this;

  self.__ = {};
  self.options = options || {};

  var array;
  if(Buffer.is_buffer(data)) {
    array = from_buffer(data); 
  } else if (val instanceof Object) {
    array = data;
  } else {
    throw new Error("Unknown value type");
  }

  var key;
  for (key in array) {
    if(array.hasOwnProperty(key)){
      self[key] = array[key];
    }
  }

  return self;
}

Object.defineProperties(Packet.prototype, {
  op: {
    get: function () { return this.__.op },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && x <= 255){
        this.__.op = x;
      } else {
        // XXX: we probably shouldn't throw here!
        throw new Error("Supplied op isn't an integer between 0 and 255");
      }
    },
  },
  htype: {
    get: function () { return this.__.htype; },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && x <= 255){
        this.__.htype = x;
      } else {
        throw new Error("Supplied htype isn't an integer between 0 and 255");
      }
    }
  },
  hlen: {
    get: function () { return this.__.hlen; },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && x <= 255){
        this.__.hlen = x;
      } else {
        throw new Error("Supplied hlen isn't an integer between 0 and 255");
      }
    }
  },
  hops: {
    get: function () { return this.__.hops; },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && x <= 255){
        this.__.hops = x;
      } else {
        throw new Error("Supplied hlen isn't an integer between 0 and 255");
      }
    }
  },
  xid: {
    get: function () { return this.__.xid; },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && <= 2147483647) {
        this.__.xid = x;
      } else {
        throw new Error("Supplied xid isn't a 32-bit unsigned integer");
      }
    }
  },
  secs: {
    get: function () { return this.__.secs; },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && x <= 65535) {
        this.__.secs = x;
      } else {
        throw new Error("Supplied secs isn't a 16-bit unsigned integer");
      }
    }
  },
  flags: {
    get: function () { return this.__.flags; },
    set: function (x) {
      if(Number.isInteger(x) && x >= 0 && x <= 65535) {
        this.__.flags = x;
      } else {
        throw new Error("Supplied flags isn't a 16-bit unsigned integer"); 
      }
    }
  },
  ciaddr: {
    get: function () { return this.__.ciaddr; },
    set: function (x) {
      // this is a special case where the client needs to explicitly state
      // that it doesn't have an IP
      if(net.isIPv4(x) || x == 0) {
        this.__.ciaddr = x;
      } else {
        throw new Error("Supplied ciaddr isn't a valid IP address (or zero)");
      }
    }
  },
  yiaddr: {
    get: function () { return this.__.ciaddr; },
    set: function (x) {
      if(net.isIPv4(x)){
        this.__.yiaddr = x;
      } else {
        throw new Error("Supplied yiaddr isn't a valid IP address");
      }
    }
  },
  siaddr: {
    get: function () { return this.__.siaddr; },
    set: function (x) {
      if(net.isIPv4(x)){
        this.__.siaddr = x;
      } else {
        throw new Error("Supplied siaddr isn't a valid IP address");
      }
    }
  },
  giaddr: {
    get: function () { return this.__.giaddr; },
    set: function (x) {
      if(net.isIPv4(x)) {
        this.__.giaddr = x;
      } else {
        throw new Error("Supplied giaddr isn't a valid IP address");
      }
    }
  },
  chaddr: {
    get: function() { return this.__.chaddr; },
    set: function (x) {
      this.__.chaddr = x; // XXX - how do we want to test this field?
    }
  
  },
  sname: {
    get: function () { return this.__.sname; },
    set: function (x) {
      if(x.length <= 64) {
        this.__.sname = x;
      } else {
        throw new Error("Supplied sname is too long");
      }
    }
  },
  file: {
    get: function () { return this.__.file; },
    set: function (x) {
      if(x.length <= 128) {
        this.__.file = x;
      } else {
        throw new Error("Supplied file is too long");
      }
    }
  }
});

Packet.prototype.from_buffer = function(b) {
  var self = this;
  var options, ret;
  ret = {
    op:     b[0],
    htype:  b[1],
    hlen:   b.readUInt8(2),
    hops:   b.readUInt8(3),
    xid:    b.readUInt32BE(4),
    secs:   b.readUInt16BE(8),
    flags:  b.readUInt16BE(10),
    ciaddr: utils.readIp(b, 12),
    yiaddr: utils.readIp(b, 16),
    siaddr: utils.readIp(b, 20),
    giaddr: utils.readIp(b, 24),
    chaddr: utils.readMacAddress(b.slice(28, 28 + b.readUInt8(2))),
    sname:  stripBinNull(b.toString('ascii', 44, 108)),
    file:   stripBinNull(b.toString('ascii', 108, 236)),
    options: {}
  };
  options = b.slice(240);
  
  self.options.decode_handler(options, ret.options); 

  return new Packet(ret);
};

Packet.prototype.to_buffer = function() {
  var self = this;
  var buffer, hex, i, key, octet, opt, padded, pos, value, _i, _j, _k, _l, _len, _len1, _len2, _len3, _ref, _ref1, _ref2, _ref3;
  buffer = new Buffer(512, 'ascii');
  buffer[0] = self.op;
  buffer[1] = self.htype;
  buffer.writeUInt8(self.hlen, 2);
  buffer.writeUInt8(self.hops, 3);
  buffer.writeUInt32BE(self.xid, 4);
  buffer.writeUInt16BE(self.secs, 8);
  buffer.writeUInt16BE(self.flags, 10);
  pos = 12;
  _ref = ["ciaddr", "yiaddr", "siaddr", "giaddr"];
  for (_i = 0, _len = _ref.length; _i < _len; _i++) {
    key = _ref[_i];
    _ref1 = (self[key] || "0.0.0.0").split(".");
    for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
      octet = _ref1[_j];
      buffer.writeUInt8(parseInt(octet, 10), pos++);
    }
  }
  _ref2 = self.chaddr.split(':');
  for (_k = 0, _len2 = _ref2.length; _k < _len2; _k++) {
    hex = _ref2[_k];
    buffer[pos++] = parseInt(hex, 16);
  }
  buffer.fill(0, 43, 235);
  buffer.write(self.sname, 43, 64, 'ascii');
  buffer.write(self.fname, 109, 128, 'ascii');
  pos = 236;
  _ref3 = [99, 130, 83, 99];
  for (_l = 0, _len3 = _ref3.length; _l < _len3; _l++) {
    i = _ref3[_l];
    buffer[pos++] = i;
  }
  pos = 240;


  for (opt in self.options) {
    if(self.options.hasOwnProperty(opt)){
      value = self.options[opt];
      var converter = get_convert(opt);
      pos = converter.encode(buffer, opt, value, pos);
    }
  }
  buffer[pos] = 255;
  padded = new Buffer(pos, 'ascii');
  buffer.copy(padded, 0, 0, pos);
  return padded;
};

function stripBinNull(str) {
  var pos;
  pos = str.indexOf('\u0000');
  if (pos === -1) {
    return str;
  } else {
    return str.substr(0, pos);
  }
}

module.exports = {
  Packet: Packet,
  fromBuffer: fromBuffer,
  toBuffer: toBuffer
};

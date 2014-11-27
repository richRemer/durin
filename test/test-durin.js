var durin = require(".."),
    expect = require("expect.js"),
    password = "password";

describe("durin module", function() {
    it("should be a function", function() {
        expect(durin).to.be.a("function");
    });
    
    it("should return an updated durin with new options", function() {
        var quickDurin = durin({iterations: 1});
        expect(durin.iterations).to.be.above(1000);
        expect(quickDurin.iterations).to.be(1);
        expect(quickDurin.saltLength).to.be(durin.saltLength);
        expect(quickDurin.keyLength).to.be(durin.keyLength);
    });
});

describe("durin.isHash(string)", function() {
    it("should return boolean indicating if string is a hash", function() {
        expect(durin.isHash("pbkdf2$00$1$00")).to.be(true);
        expect(durin.isHash("foo")).to.be(false);
    });
});

describe("durin.hashPassword(string, function)", function() {
    it("should pass an encoded hash", function(done) {
        durin.hashPassword(password, function(hash) {
            expect(durin.isHash(hash)).to.be(true);
            done();
        });
    });
});

describe("durin.verifyPassword(string, string, function)", function() {
    var hashOptions = {saltLength: 8, keyLength: 8, iterations: 1},
        hash;
    
    before(function(done) {
        durin(hashOptions).hashPassword(password, function(h) {
            hash = h;
            done();
        });
    });

    it("should pass verified/updated hash or false", function(done) {
        durin(hashOptions).verifyPassword(password, hash, function(verified) {
            expect(verified).to.be(hash);
            
            var updated = durin(hashOptions)({iterations: 2});
            updated.verifyPassword(password, hash, function(verified) {
                expect(verified).to.be.a("string");
                expect(durin.isHash(verified)).to.be(true);
                expect(verified).to.not.be(hash);
                done();
            });
        });
    });
});

const assert = require('assert')
const auth = require('..')

function request (authorization) {
  return {
    headers: {
      authorization: authorization
    }
  }
}

describe('auth(req)', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        assert.throws(auth, /argument req is required/)
      })

      it('should accept a request', function () {
        const req = request('basic Zm9vOmJhcg==')
        const credentials = auth(req)
        assert.equal(credentials.name, 'foo')
        assert.equal(credentials.pass, 'bar')
      })

      it('should accept a request without semicolon', function () {
        const req = request('basic Zm9v')
        const credentials = auth(req)
        assert.equal(credentials.name, 'foo')
      })

      it('should reject null', function () {
        assert.throws(auth.bind(null, null), /argument req is required/)
      })

      it('should reject a number', function () {
        assert.throws(auth.bind(null, 42), /argument req is required/)
      })

      it('should reject an object without headers', function () {
        assert.throws(auth.bind(null, {}), /argument req is required/)
      })
    })
  })

  describe('with no Authorization field', function () {
    it('should return undefined', function () {
      const req = request()
      assert.strictEqual(auth(req), undefined)
    })
  })

  describe('with malformed Authorization field', function () {
    it('should return undefined', function () {
      const req = request('Something')
      assert.strictEqual(auth(req), undefined)
    })
  })

  describe('with malformed Authorization scheme', function () {
    it('should return undefined', function () {
      const req = request('basic_Zm9vOmJhcg==')
      assert.strictEqual(auth(req), undefined)
    })
  })

  describe('without password', function () {
    it('should return username only, password undefined', function () {
      const req = request('basic Zm9v')
      const credentials = auth(req)
      assert.equal(credentials.name, 'foo')
      assert.strictEqual(credentials.pass, undefined)
    })
  })

  describe('with valid credentials', function () {
    it('should return .name and .pass', function () {
      const req = request('basic Zm9vOmJhcg==')
      const credentials = auth(req)
      assert.equal(credentials.name, 'foo')
      assert.equal(credentials.pass, 'bar')
    })
  })

  describe('with empty password', function () {
    it('should return .name and .pass', function () {
      const req = request('basic Zm9vOg==')
      const credentials = auth(req)
      assert.equal(credentials.name, 'foo')
      assert.equal(credentials.pass, '')
    })
  })

  describe('with empty userid', function () {
    it('should return .name and .pass', function () {
      const req = request('basic OnBhc3M=')
      const credentials = auth(req)
      assert.equal(credentials.name, '')
      assert.equal(credentials.pass, 'pass')
    })
  })

  describe('with empty userid and pass', function () {
    it('should return .name and .pass', function () {
      const req = request('basic Og==')
      const credentials = auth(req)
      assert.equal(credentials.name, '')
      assert.equal(credentials.pass, '')
    })
  })

  describe('with colon in pass', function () {
    it('should return .name and .pass', function () {
      const req = request('basic Zm9vOnBhc3M6d29yZA==')
      const credentials = auth(req)
      assert.equal(credentials.name, 'foo')
      assert.equal(credentials.pass, 'pass:word')
    })
  })
})

describe('auth.parse(string)', function () {
  describe('with undefined string', function () {
    it('should return undefined', function () {
      assert.strictEqual(auth.parse(), undefined)
    })
  })

  describe('with malformed string', function () {
    it('should return undefined', function () {
      assert.strictEqual(auth.parse('Something'), undefined)
    })
  })

  describe('with malformed scheme', function () {
    it('should return undefined', function () {
      assert.strictEqual(auth.parse('basic_Zm9vOmJhcg=='), undefined)
    })
  })

  describe('with malformed credentials', function () {
    it('should return undefined', function () {
      const credentials = auth.parse('basic Zm9v')
      assert.equal(credentials.name, 'foo')
      assert.strictEqual(credentials.pass, undefined)
    })
  })

  describe('with valid credentials', function () {
    it('should return .name and .pass', function () {
      const credentials = auth.parse('basic Zm9vOmJhcg==')
      assert.equal(credentials.name, 'foo')
      assert.equal(credentials.pass, 'bar')
    })
  })

  describe('with empty password', function () {
    it('should return .name and .pass', function () {
      const credentials = auth.parse('basic Zm9vOg==')
      assert.equal(credentials.name, 'foo')
      assert.equal(credentials.pass, '')
    })
  })

  describe('with empty userid', function () {
    it('should return .name and .pass', function () {
      const credentials = auth.parse('basic OnBhc3M=')
      assert.equal(credentials.name, '')
      assert.equal(credentials.pass, 'pass')
    })
  })

  describe('with empty userid and pass', function () {
    it('should return .name and .pass', function () {
      const credentials = auth.parse('basic Og==')
      assert.equal(credentials.name, '')
      assert.equal(credentials.pass, '')
    })
  })

  describe('with colon in pass', function () {
    it('should return .name and .pass', function () {
      const credentials = auth.parse('basic Zm9vOnBhc3M6d29yZA==')
      assert.equal(credentials.name, 'foo')
      assert.equal(credentials.pass, 'pass:word')
    })
  })
})

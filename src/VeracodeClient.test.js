/**
 * We need to disable no-callback-in-promise rule because we have to call Jest's
 * done inside of promise handlers.
 */

/* eslint promise/no-callback-in-promise:0 */
const VeracodeClient = require("./VeracodeClient");
const crypto = require("crypto");
const request = require("request");
const { URL } = require("url");
const fs = require("fs");
const archiver = require("archiver");

const mockApiId = "fake";
const mockApiSecret = "also-fake";
const mockNonce = Buffer.from("asdf");
const mockDate = new Date("2001-09-11T08:46:00");
const realDateNow = Date.now;
const veracodeClient = new VeracodeClient(mockApiId, mockApiSecret);

jest.spyOn(crypto, "randomBytes").mockImplementation((size) => {
  expect(typeof size).toBe("number");
  return mockNonce;
});

jest.mock("request");
jest.mock("fs");
jest.mock("archiver");

function computeHash (data, key) {
  const hmac = crypto.createHmac("sha256", key);
  hmac.update(data);
  return hmac.digest();
}

function mockAuthHeader (url, method) {
  const data = `id=${mockApiId}&host=${url.host}&url=${url.pathname + url.search}&method=${method}`;

  const hashedNonce = computeHash(mockNonce, Buffer.from(mockApiSecret, "hex"));
  const hashedDate = computeHash(mockDate.toString(), hashedNonce);
  const hashedVersionCode = computeHash("vcode_request_version_1", hashedDate);
  const signature = computeHash(data, hashedVersionCode);

  const authParam = `id=${mockApiId},ts=${mockDate.toString()},nonce=${mockNonce.toString("hex")},sig=${signature.toString("hex")}`;
  return `VERACODE-HMAC-SHA-256 ${authParam}`;
}

function baseRequestArg (url, method = "POST") {
  return {
    method: method,
    uri: url,
    headers: {
      "Authorization": mockAuthHeader(url, method),
    },
    gzip: true,
  };
}

beforeAll(() => {
  Date.now = jest.fn().mockReturnValue(mockDate);
});

afterAll(() => {
  Date.now = realDateNow;
});

test("#calculateAuthorizationHeader", async () => {
  const url = new URL("action.do", veracodeClient.apiBase);
  const authHeader = veracodeClient.calculateAuthorizationHeader(url, "GET");
  expect(authHeader).toBe(mockAuthHeader(url, "GET"));
});

describe("constructor", () => {
  test("throws error when apiId and apiKey are undefined", async () => {
    // We have to wrap the constructor in a function because expect doesn't work
    // with constructors.
    expect(() => {
      // eslint-disable-next-line no-new
      new VeracodeClient();
    }).toThrow("must be defined");
  });
});

describe("#_xmlRequest", () => {
  test("parses xml", async () => {
    request.mockResolvedValue(`
    <test account_id="123" app_id="456">
      <nested nested_id="789"/>
    </test>
    `);
    const response = await veracodeClient._xmlRequest({ endpoint: "mytest.do" });
    const expectedUrl = new URL("mytest.do", veracodeClient.apiBase);
    expect(request).toBeCalledWith(baseRequestArg(expectedUrl, "GET"));
    expect(response).toEqual({
      test: {
        _attributes: {
          account_id: "123",
          app_id: "456",
        },
        nested: {
          _attributes: {
            nested_id: "789",
          },
        },
      },
    });
  });

  test("can return xml", async () => {
    const xml = `
    <test account_id="123" app_id="456">
      <nested nested_id="789"/>
    </test>
    `;
    request.mockResolvedValue(xml);
    const xmlVeracodeClient = new VeracodeClient(mockApiId, mockApiSecret, true);
    const response = await xmlVeracodeClient._xmlRequest({ endpoint: "mytest.do" });
    const expectedUrl = new URL("mytest.do", xmlVeracodeClient.apiBase);
    expect(request).toBeCalledWith(baseRequestArg(expectedUrl, "GET"));
    expect(response).toEqual(xml);
  });

  test("throws error", async () => {
    request.mockResolvedValue("<error>Baby did a boom boom</error>");
    expect(veracodeClient._xmlRequest({ endpoint: "mytest.do" })).rejects.toThrow("Baby did a boom boom");
  });
});

describe("#_restRequest", () => {
  test("returns _embedded", async () => {
    request.mockResolvedValue(`
    {
      "_embedded": {
        "applications": [{
          "guid": "some-long-guid",
          "id": 123456
        }]
      }
    }
    `);
    const response = await veracodeClient._restRequest({ endpoint: "applications" });
    const expectedUrl = new URL("applications", veracodeClient.apiBaseRest);
    expect(request).toBeCalledWith({
      method: "GET",
      uri: expectedUrl,
      headers: {
        "Authorization": mockAuthHeader(expectedUrl, "GET"),
      },
    });
    expect(response).toEqual([{
      guid: "some-long-guid",
      id: 123456,
    }]);
  });

  test("returns empty array if no _embedded", async () => {
    request.mockResolvedValue("{}");
    const response = await veracodeClient._restRequest({ endpoint: "applications" });
    expect(response).toEqual([]);
  });

  test("calls request with query params if they are provided", async () => {
    await veracodeClient._restRequest({ endpoint: "findings", query: "modified_after=2018-12-31" });
    const expectedUrl = new URL("findings?modified_after=2018-12-31", veracodeClient.apiBaseRest);
    expect(request).toHaveBeenCalledWith({
      method: "GET",
      uri: expectedUrl,
      headers: {
        "Authorization": mockAuthHeader(expectedUrl, "GET"),
      },
    });
  });

  test("pages through results", async () => {
    const nextLink = `${veracodeClient.apiBaseRest}applications?limit=100&page=1`;
    request.mockResolvedValueOnce(`
    {
      "_embedded": {
        "applications": [{
          "guid": "some-long-guid",
          "id": 123456
        }]
      },
      "_links": {
        "next": {
          "href": "${nextLink}"
        }
      }
    }
    `);
    request.mockResolvedValueOnce(`
    {
      "_embedded": {
        "applications": [{
          "guid": "some-other-guid",
          "id": 414141
        }]
      },
      "_links": {}
    }
    `);
    const response = await veracodeClient._restRequest({ endpoint: "applications" });
    const expectedUrl = new URL("applications", veracodeClient.apiBaseRest);
    expect(request).toBeCalledTimes(2);
    expect(request).toBeCalledWith({
      method: "GET",
      uri: expectedUrl,
      headers: {
        "Authorization": mockAuthHeader(expectedUrl, "GET"),
      },
    });
    expect(request).toBeCalledWith({
      method: "GET",
      uri: new URL(nextLink),
      headers: {
        "Authorization": mockAuthHeader(new URL(nextLink), "GET"),
      },
    });
    expect(response).toEqual([{
      guid: "some-long-guid",
      id: 123456,
    }, {
      guid: "some-other-guid",
      id: 414141,
    }]);
  });

  test("supports disabling paging", async () => {
    request.mockResolvedValueOnce(`
    {
      "_embedded": {
        "applications": [{
          "guid": "some-long-guid",
          "id": 123456
        }]
      },
      "_links": {
        "next": {
          "href": "${veracodeClient.apiBaseRest}applications?limit=100&page=1"
        }
      }
    }
    `);
    const response = await veracodeClient._restRequest({ endpoint: "applications" }, false);
    const expectedUrl = new URL("applications", veracodeClient.apiBaseRest);
    expect(request).toBeCalledTimes(1);
    expect(request).toBeCalledWith({
      method: "GET",
      uri: expectedUrl,
      headers: {
        "Authorization": mockAuthHeader(expectedUrl, "GET"),
      },
    });
    expect(response).toEqual([{
      guid: "some-long-guid",
      id: 123456,
    }]);
  });
});

describe("#uploadFile", async () => {
  test("uploads file with all options", async () => {
    request.mockResolvedValue("<filelist><file/></filelist>");

    await veracodeClient.uploadFile({ appId: "123", file: "my_lil_file.zip", sandboxId: "456", saveAs: "my_lil_file" });
    expect(fs.createReadStream).toBeCalledWith("my_lil_file.zip");

    const expectedUrl = new URL("uploadfile.do", veracodeClient.apiBase);
    expect(request).toBeCalledWith({
      ...baseRequestArg(expectedUrl),
      formData: {
        app_id: "123",
        file: undefined,
        sandbox_id: "456",
        save_as: "my_lil_file",
      },
    });
  });

  test("doesn't include sandbox_id or save_as if not provided in options", async () => {
    request.mockResolvedValue("<filelist><file/></filelist>");

    await veracodeClient.uploadFile({ appId: "123", file: "my_lil_file.zip" });
    expect(fs.createReadStream).toBeCalledWith("my_lil_file.zip");

    const expectedUrl = new URL("uploadfile.do", veracodeClient.apiBase);
    expect(request).toBeCalledWith({
      ...baseRequestArg(expectedUrl),
      formData: {
        app_id: "123",
        file: undefined,
      },
    });
  });
});

describe("#createZipArchive", async () => {
  let mockWriteStream = {
    registeredListeners: {},

    on: function (event, listener) {
      this.registeredListeners[event] = listener;
    },

    simulate: function (event, ...args) {
      this.registeredListeners[event](...args);
    },
  };

  let mockArchiver = {
    registeredListeners: {},

    on: function (event, listener) {
      this.registeredListeners[event] = listener;
    },

    simulate: function (event, ...args) {
      this.registeredListeners[event](...args);
    },

    pointer: jest.fn().mockReturnValue(420),
    pipe: jest.fn(),
    glob: jest.fn(),
    finalize: jest.fn(),
  };

  beforeAll(async () => {
    fs.createWriteStream.mockReturnValue(mockWriteStream);
    archiver.mockReturnValue(mockArchiver);
  });

  beforeEach(async () => {
    mockArchiver.registeredListeners = {};
    mockWriteStream.registeredListeners = {};
  });

  test("returns archive size", async done => {
    veracodeClient.createZipArchive("testdir", "test", null).then((archiveSize) => {
      expect(archiveSize).toBe(420);
      return done();
    }).catch(err => { throw err; });
    mockWriteStream.simulate("close");
  });

  test("rejects on fatal warning", async done => {
    veracodeClient.createZipArchive("testdir", "test", null).catch((warning) => {
      expect(warning.code).toBe(1);
      done();
    }).catch(err => { throw err; });
    mockArchiver.simulate("warning", { code: 1 });
  });

  test("logs to console with non-fatal warnings", async done => {
    jest.spyOn(console, "log").mockImplementationOnce(() => {});
    veracodeClient
      .createZipArchive("testdir", "test", null)
      .then(() => {
        return done();
      })
      .catch(err => { throw err; });
    mockArchiver.simulate("warning", { code: "ENOENT", message: "do not do that plz" });
    mockWriteStream.simulate("close");
    expect(console.log).toHaveBeenCalledWith("Warning: do not do that plz");
  });

  test("rejects on archiver error", async done => {
    veracodeClient.createZipArchive("testdir", "test", null).catch((error) => {
      expect(error).toEqual({ code: "borked", message: "it borked" });
      done();
    });
    mockArchiver.simulate("error", { code: "borked", message: "it borked" });
  });
});

describe("#summaryReport", () => {
  test("get summary report with all options", async () => {
    request.mockResolvedValue("<summaryReport></summaryReport>");

    await veracodeClient.summaryReport({ buildId: "123" });

    const expectedUrl = new URL("summaryreport.do", veracodeClient.apiBase4);
    expect(request).toBeCalledWith({
      ...baseRequestArg(expectedUrl),
      form: {
        build_id: "123",
      },
    });
  });
});

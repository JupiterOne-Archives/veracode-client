// Native libs
const crypto = require("crypto");
const { URL } = require("url");
const fs = require("fs");

// 3rd party libs
const got = require("got");
const FormData = require("form-data");
const convert = require("xml-js");
const archiver = require("archiver");

/* Veracode HTTP request wrapper */
class VeracodeClient {
  constructor (apiId, apiKey, returnXml = false) {
    // Errors returned on undefined API credentials are too confusing
    if (!(apiId && apiKey)) {
      throw new Error("Both Veracode API ID and key must be defined");
    }

    this.apiId = apiId;
    this.apiKey = apiKey;
    this.returnXml = returnXml;

    this.hashAlgorithm = "sha256";
    this.authScheme = "VERACODE-HMAC-SHA-256";
    this.requestVersion = "vcode_request_version_1";
    this.nonceSize = 16;

    this.apiBase = "https://analysiscenter.veracode.com/api/5.0/";
    this.apiBase4 = "https://analysiscenter.veracode.com/api/4.0/"; // some functionality is only available in v4
    this.apiBaseRest = "https://api.veracode.com/appsec/v1/";
  }

  /* Authorization Header */

  currentDateStamp () {
    return Date.now().toString();
  }

  newNonce (size) {
    return crypto.randomBytes(size);
  }

  computeHash (data, key) {
    const hmac = crypto.createHmac(this.hashAlgorithm, key);
    hmac.update(data);
    return hmac.digest();
  }

  calculateDataSignature (apiKey, nonceBytes, dateStamp, data) {
    const kNonce = this.computeHash(nonceBytes, Buffer.from(apiKey, "hex"));
    const kDate = this.computeHash(dateStamp, kNonce);
    const kSignature = this.computeHash(this.requestVersion, kDate);
    return this.computeHash(data, kSignature);
  }

  calculateAuthorizationHeader (urlString, httpMethod) {
    const url = new URL(urlString);
    const hostName = url.hostname;
    const veraURL = url.pathname + url.search;
    const data = `id=${
      this.apiId
    }&host=${hostName}&url=${veraURL}&method=${httpMethod}`;
    const dateStamp = this.currentDateStamp();
    const nonceBytes = this.newNonce(this.nonceSize);
    const dataSignature = this.calculateDataSignature(
      this.apiKey,
      nonceBytes,
      dateStamp,
      data,
    );
    const authorizationParam = `id=${
      this.apiId
    },ts=${dateStamp},nonce=${nonceBytes.toString(
      "hex",
    )},sig=${dataSignature.toString("hex")}`;
    return `${this.authScheme} ${authorizationParam}`;
  }

  _form (form) {
    const formdata = new FormData();
    for (const key in form) {
      formdata.append(key, form[key]);
    }
  }

  /* Veracode XML API Wrapper */

  async _xmlRequest (options) {
    const uri = new URL(options.endpoint, options.apiBase || this.apiBase);
    const formData = options.form || options.formData;
    const method = formData ? "POST" : "GET";
    const body = formData ? { body: this._form(formData) } : {};
    const xmlResponse = await got(uri, {
      ...body,
      method,
      headers: {
        Authorization: this.calculateAuthorizationHeader(uri, method),
      },
      responseType: "text",
      resolveBodyOnly: true,
      form: options.form,
      formData: options.formData,
      gzip: true, // Veracode recommends to use GZIP whenever possible
    });

    if (this.returnXml) {
      return xmlResponse;
    }

    const jsResponse = convert.xml2js(xmlResponse, { compact: true });

    if (jsResponse.error) {
      throw new Error(jsResponse.error._text);
    }

    return jsResponse;
  }

  /* Veracode REST API Wrapper */

  async _restRequest (options, page = true) {
    let uriString = options.endpoint;
    uriString = options.query
      ? options.endpoint + "?" + options.query
      : options.endpoint;
    const method = "GET";

    let uri = new URL(uriString, options.apiBase || this.apiBaseRest);
    const resources = [];

    /* eslint no-unmodified-loop-condition:0 */
    do {
      const responseParsed = await got(uri, {
        method,
        headers: {
          Authorization: this.calculateAuthorizationHeader(uri, method),
        },
        responseType: "json",
        resolveBodyOnly: true,
      });

      const pathParts = options.endpoint.split("/");
      const resource = pathParts[pathParts.length - 1];

      resources.push(...this.getEmbedded(responseParsed, resource));

      if (responseParsed._links && responseParsed._links.next) {
        uri = new URL(responseParsed._links.next.href);
      } else {
        uri = null;
      }
    } while (uri && page);

    return resources;
  }

  /* Veracode API functions */

  async getApplications () {
    return this._restRequest({
      endpoint: "applications",
    });
  }

  async getFindings (applicationGuid, modifiedAfter) {
    const requestOptions = {
      endpoint: `applications/${applicationGuid}/findings`,
    };

    if (modifiedAfter) {
      requestOptions.query = `modified_after=${modifiedAfter}`;
    }

    return this._restRequest(requestOptions);
  }

  // "The getapplist.do call compiles a list of the applications in the portfolio."
  async getAppList () {
    const response = await this._xmlRequest({
      endpoint: "getapplist.do",
    });
    /* istanbul ignore next */
    return this.returnXml ? response : this.controlledArray(response.applist.app);
  }

  // "The getsandboxlist.do call returns a list of all the sandboxes associated with the specified application."
  async getSandboxList (options) {
    const response = await this._xmlRequest({
      endpoint: "getsandboxlist.do",
      form: {
        app_id: options.appId,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : this.controlledArray(response.sandboxlist.sandbox);
  }

  // "The createsandbox.do call creates a sandbox for the specified application."
  async createSandbox (options) {
    const response = await this._xmlRequest({
      endpoint: "createsandbox.do",
      form: {
        app_id: options.appId,
        sandbox_name: options.sandboxName,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.sandboxinfo;
  }

  // "The getbuildlist call produces a list of the policy or sandbox scans of the application that are currently in progress or already complete."
  async getBuildList (options) {
    const response = await this._xmlRequest({
      endpoint: "getbuildlist.do",
      form: {
        app_id: options.appId,
        sandbox_id: options.sandboxId,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : this.controlledArray(response.buildlist.build);
  }

  // The getappbuilds.do call compiles a detailed list of applications and statuses, including all the application and scan profile data
  // Does not include sandboxes
  async getAppBuilds (options = {}) {
    const response = await this._xmlRequest({
      endpoint: "getappbuilds.do",
      apiBase: this.apiBase4, // note the use of API v4, this call is not available in v5
      form: {
        report_changed_since: options.reportChangedSince,
        only_latest: options.onlyLatest,
        include_in_progress: options.includeInProgress,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : this.controlledArray(response.applicationbuilds.application);
  }

  // "The summaryreport.do call returns a summary XML report of the scan results for the specified build."
  async summaryReport (options) {
    const response = await this._xmlRequest({
      endpoint: "summaryreport.do",
      apiBase: this.apiBase4, // note the use of API v4, this call is not available in v5
      form: {
        build_id: options.buildId,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.summaryreport;
  }

  // "The detailedreport.do call returns a detailed XML report of the scan results for the specified build."
  async detailedReport (options) {
    const response = await this._xmlRequest({
      endpoint: "detailedreport.do",
      form: {
        build_id: options.buildId,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.detailedreport;
  }

  // "The uploadfile.do call uploads a file to an existing application or creates a new build if one does not already exist."
  async uploadFile (options) {
    const formData = {
      app_id: options.appId,
      file: fs.createReadStream(options.file),
    };

    // Can't have undefined or null values in formData above:
    // https://github.com/form-data/form-data/issues/137
    if (options.sandboxId) {
      formData.sandbox_id = options.sandboxId;
    }

    if (options.saveAs) {
      formData.save_as = options.saveAs;
    }

    const response = await this._xmlRequest({
      endpoint: "uploadfile.do",
      formData,
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.filelist;
  }

  // "The beginprescan call runs the prescan of the application and determines whether the auto-scan feature is on or off"
  async beginPrescan (options) {
    const response = await this._xmlRequest({
      endpoint: "beginprescan.do",
      form: {
        app_id: options.appId,
        auto_scan: options.autoScan,
        sandbox_id: options.sandboxId,
        scan_all_nonfatal_top_level_modules:
          options.scanAllNonfatalTopLevelModules,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.buildinfo;
  }

  // "Creates a new application in the portfolio."
  async createApp (options) {
    const response = await this._xmlRequest({
      endpoint: "createapp.do",
      form: {
        app_name: options.appName, // required
        description: options.description,
        vendor_id: options.vendorId,
        business_criticality: options.businessCriticality, // required
        policy: options.policy,
        business_unit: options.businessUnit,
        business_owner: options.businessOwner,
        business_owner_email: options.businessOwnerEmail,
        teams: options.teams,
        origin: options.origin,
        industry: options.industry,
        app_type: options.appType,
        deployment_method: options.deploymentMethod,
        web_application: options.webApplication,
        archer_app_name: options.archerAppName,
        tags: options.tags,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.appinfo;
  }

  // "The createbuild.do call creates a new build of an existing application in the portfolio."
  async createBuild (options) {
    const response = await this._xmlRequest({
      endpoint: "createbuild.do",
      form: {
        app_id: options.appId,
        version: options.appVersion,
        lifecycle_stage: options.lifecycleStage,
        launch_date: options.launchDate,
        sandbox_id: options.sandboxId,
        legacy_scan_engine: options.legacyScanEngine,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.buildinfo;
  }

  // "The getbuildinfo call provides information about the most recent or specific scan of the application."
  async getBuildInfo (options) {
    const response = await this._xmlRequest({
      endpoint: "getbuildinfo.do",
      form: {
        app_id: options.appId,
        build_id: options.buildId,
        sandbox_id: options.sandboxId,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : response.buildinfo;
  }

  // "The deleteapp.do call deletes an existing application in the portfolio."
  async deleteApp (options) {
    const response = await this._xmlRequest({
      endpoint: "deleteapp.do",
      form: {
        app_id: options.appId,
      },
    });
    /* istanbul ignore next */
    return this.returnXml ? response : this.controlledArray(response.applist.app);
  }

  // Creates a zip archive of a given directory ignoring provided patterns (glob)
  createZipArchive (directory, zipName, ignore) {
    return new Promise((resolve, reject) => {
      const output = fs.createWriteStream(zipName);
      const archive = archiver("zip", {
        zlib: { level: 9 },
      });

      output.on("close", () => {
        // return size of archive in bytes
        resolve(archive.pointer());
      });

      // "good practice to catch warnings (ie stat failures and other non-blocking errors)"
      archive.on("warning", warn => {
        if (warn.code === "ENOENT") {
          // log warning
          console.log(`Warning: ${warn.message}`);
        } else {
          reject(warn);
        }
      });

      // "good practice to catch this error explicitly"
      archive.on("error", reject);

      // pipe archive data to the file
      archive.pipe(output);

      archive.glob(
        "**/*",
        {
          cwd: directory,
          ignore,
        },
        {},
      );

      archive.finalize();
    });
  }

  // xml deserialization returns array if multiple objects, and single object if just one
  // this function ensures an [empty] array is returned so downstream can safely process it
  controlledArray (a) {
    return typeof a === "undefined" ? [] : [].concat(a);
  }

  getEmbedded (response, resource) {
    if (response._embedded) {
      return response._embedded[resource];
    } else {
      return [];
    }
  }
}

module.exports = VeracodeClient;

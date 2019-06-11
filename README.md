# veracode-client

REST API client for Veracode. Uses xml-js to parse xml. Functionality follows
[the original Veracode API
documentation](https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/FhxRdiWf5qejrtajmjGtpw).

## Install

```bash
yarn add @jupiterone/veracode-client
```

## Usage

For convenience, all methods use objects to pass parameters, e.g. when the
original function expects parameters `app_id` and `sandbox_id`, VeracodeClient
function would be called the following object as parameter: `{appId, sandboxId}`

Please see tests for more examples.

Usage example:

```javascript
const os = require('os');

const VeracodeClient = require('@jupiterone/veracode-client');

const veraClient = new VeracodeClient({
  apiId: process.env.VERA_ID,
  apiKey: process.env.VERA_KEY
});

const testAppInfo = {
  appName: 'TestApp',
  appVersion: 'TestVersion',
  sandboxName: 'TestSandbox',
  businessCriticality: 'High', // 'High' is used by security-scan
  teams: 'Security', // Only security team will get notifications about this test app
  autoScan: true, // Required to start scan automatically after pre-scan
  description: 'Test application, safe to delete'
};

const appId = (await veraClient.createApp(testAppInfo)).application._attributes.app_id;
console.log('New app ID:', appId);

testAppInfo.appId = app_id;
const sandboxId = (await veraClient.createSandbox(testAppInfo)).sandbox._attributes.sandbox_id;
console.log('New Sandbox ID:', sandboxId);

testAppInfo.sandboxId = sandboxId;
const buildId = (await veraClient.createBuild(testAppInfo)).build._attributes.build_id;
console.log('New Build ID:', buildId);

testAppInfo.file = path.join(os.tmpdir(), `testapp.zip`);
await veraClient.createZipArchive('/my/source/code/location', testAppInfo.file, [ 'node_modules/**/*' ]);
const fileId = (await veraClient.uploadFile(testAppInfo)).file._attributes.file_id;
console.log('New File ID:', fileId);

const scanId = await veraClient.beginPrescan(testAppInfo).build.analysis_unit._attributes.build_id;
console.log('New Scan ID:', scanId);
```

## Development

To run the integration tests, you'll need a Veracode API id and secret. Follow
the [instructions on
Veracode](https://help.veracode.com/reader/LMv_dtSHyb7iIxAQznC~9w/Gv1oHnvAIwMy2gQSBrF0fA)
to obtain these credentials.

Once you have them, run this in your shell (with your id and secret substituted,
of course):

```sh
export VERA_ID=YOUR_VERACODE_ID
export VERA_KEY=YOUR_VERACODE_SECRET
```

Now you'll be able to run the integration tests with `yarn test:integration`.

## Notes

 1. Not all functions are currently implemented.

    List of implemented REST functions:

    |VeracodeClient method|API endpoint|
    |---|---|
    |getApplications|applications|
    |getFindings|applications/{applicationGUID}/findings|

    List of implemented XML functions:

    |VeracodeClient method|API endpoint|
    |---|---|
    |getAppList|getapplist.do|
    |getSandboxList|getsandboxlist.do|
    |createSandbox|createsandbox.do|
    |getBuildList|getbuildlist.do|
    |getAppBuilds|getappbuilds.do|
    |summaryReport|summaryreport.do|
    |detailedReport|detailedreport.do|
    |uploadFile|uploadfile.do|
    |beginPrescan|beginprescan.do|
    |createApp|createapp.do|
    |createBuild|createbuild.do|
    |getBuildInfo|getbuildinfo.do|
    |deleteApp|deleteapp.do|

 1. The `createZipArchive()` menthod is added to the client functionality for convenience

    Example:

    ```javascript
    await veraClient.createZipArchive('/path/to/my/repo', 'target_archive_name.zip', [ 'node_modules/**/*' ]);
    ```

 1. Only API ID and KEY authentication method supported

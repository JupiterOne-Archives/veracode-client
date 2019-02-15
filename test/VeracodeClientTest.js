const fs = require('fs');
const path = require('path');

const jspath = require('jspath');
const moment = require('moment');
const tempy = require('tempy');

const VeracodeClient = require('../src/VeracodeClient');

// Something unique for each build of this repository
// Unix ms timestamp is unique enough
const somethingUnique = moment().format('x');

const testApp = {
  appName: 'veracode-client-test',
  appVersion: `test-version-${somethingUnique}`,
  sandboxName: `test-sandbox-${somethingUnique}`,
  businessCriticality: 'High', // 'High' is used by security-scan, so using it here as well
  teams: 'Security', // Only security team will get notifications about this test app
  autoScan: true, // Required to start scan automatically after pre-scan
  description: 'This application is used to test veracode-client'
};

// Ensure test application is created
test.before(async (t) => {
  const veraClient = new VeracodeClient({
    apiId: process.env.VERA_ID,
    apiKey: process.env.VERA_KEY
  });

  // Get applications list
  const getAppListResult = await veraClient.getAppList();
  t.true(Array.isArray(getAppListResult), 'Should be an array of values');

  // This is not a case only when there is no apps at Veracode at all - very unlikely scenario, and is fixed after 1st run
  if (getAppListResult.length > 0) {
    t.truthy(getAppListResult[0]._attributes.app_name, 'Elements of array should include app_name attribute');
    t.truthy(getAppListResult[0]._attributes.app_id, 'Elements of array should include app_id attribute');
    t.false(isNaN(getAppListResult[0]._attributes.app_id), 'app_id should be a number');
  }

  // Locate the test app or create it if needed
  const searchResult = jspath.apply(
    `._attributes{.app_name === "${testApp.appName}"}.app_id`,
    getAppListResult
  );

  // We want to know if there is a scenario when search for an application returns more than 1 app_id
  t.true(searchResult.length <= 1, 'Application search returned more than 1 result');

  if (searchResult.length > 0) {
    console.log('Test application was located under Application ID', searchResult[0]);
    testApp.appId = searchResult[0];
  } else {
    console.log(`Test application '${testApp.appName}' was not found in Veracode. It will be created...`);
    const createAppResult = await veraClient.createApp(testApp);
    testApp.appId = createAppResult.application._attributes.app_id;
  }
});

test.beforeEach(async (t) => {
  t.context.veraClient = new VeracodeClient({
    apiId: process.env.VERA_ID,
    apiKey: process.env.VERA_KEY
  });

  t.context.testAppInfo = testApp;
});

// All tests working with veracode API directly are serial - it does not handle async load well
test.serial('Create and delete a temp app', async (t) => {
  const tempAppInfo = {
    appName: `veracode-client-temp-${somethingUnique}`,
    businessCriticality: 'Low',
    description: 'This application is used in veracode-client unit tests. It\'s safe to remove it'
  };

  // Create a temp application
  const createAppResult = await t.context.veraClient.createApp(tempAppInfo);
  t.truthy(createAppResult.application._attributes.app_id, 'Should return app_id in new application attributes');
  t.false(isNaN(createAppResult.application._attributes.app_id), 'app_id attribute should be a number');
  await t.throws(t.context.veraClient.createApp(tempAppInfo), Error, 'Should not allow creation of another application with the same name');
  tempAppInfo.appId = createAppResult.application._attributes.app_id;

  // Delete temp application
  const deleteAppResult = await t.context.veraClient.deleteApp(tempAppInfo);
  t.truthy(deleteAppResult, 'Should return a list of apps remaining at account');
  t.true(Array.isArray(deleteAppResult), 'List of apps returned by deleteApp() should be an array');
});

test.serial('Create and start a new static scan', async (t) => {
  const testAppInfo = t.context.testAppInfo;

  // Create a new sandbox
  const createSandboxResult = await t.context.veraClient.createSandbox(testAppInfo);
  t.truthy(createSandboxResult.sandbox._attributes.sandbox_id, 'Should return a sandbox with sandbox_id attribute');
  testAppInfo.sandboxId = createSandboxResult.sandbox._attributes.sandbox_id;

  // Create a new build - allows to explicitly mark a new scan with application version
  const createBuildResult = await t.context.veraClient.createBuild(testAppInfo);
  t.truthy(createBuildResult.build._attributes.build_id, 'Should return a build with build_id attribute');
  t.truthy(createBuildResult._attributes.sandbox_id, 'Should return a sandbox_id attribute');
  t.false(isNaN(createBuildResult.build._attributes.build_id), 'build_id should be a number');
  testAppInfo.buildId = createBuildResult.build._attributes.build_id;

  // Create ZIP archive
  const targetDir = path.resolve(__dirname, '../src'); // just give it something small
  testAppInfo.file = tempy.file({name: `${testAppInfo.appVersion}.zip`});
  try {
    await t.context.veraClient.createZipArchive(targetDir, testAppInfo.file, ['node_modules/**/*']);
    t.true(fs.existsSync(testAppInfo.file, 'Should create a ZIP archive'));

    // Upload ZIP archive to Veracode
    const uploadResult = await t.context.veraClient.uploadFile(testAppInfo);
    t.truthy(uploadResult.file._attributes.file_id, 'Should return a file_id file attribute');
    testAppInfo.file_id = uploadResult.file._attributes.file_id;

    // Start static scan
    const beginPrescanResult = await t.context.veraClient.beginPrescan(testAppInfo);
    t.truthy(beginPrescanResult.build.analysis_unit._attributes.status, 'Should return a status attribute within analysis_unit');

    // Test detailedReport error - duplicated here in a hope that will be running in parallel some day
    const reportError = await t.throws(t.context.veraClient.detailedReport(testAppInfo));
    // Report for this test app is not yet available, so we expect a specific error here
    t.is(reportError.message, 'No report available.');
  } finally {
    // Delete ZIP archive
    fs.unlinkSync(testAppInfo.file);
  }
});

test.serial('Get list of builds for all applications', async (t) => {
  const getAppBuilds = await t.context.veraClient.getAppBuilds({includeInProgress: true});
  t.true(Array.isArray(getAppBuilds), 'Should be an array of values');
  t.truthy(getAppBuilds[0]._attributes.modified_date, 'Elements of array should include modified_date attribute');
});

// Scans take anything from 2-4+ hours, so using a previously completed scan
test.serial('Get report for a previous scan', async (t) => {
  const testAppInfo = t.context.testAppInfo;

  // Go through each previous build in all sandboxes and search for a completed scan
  const getSandboxListResult = await t.context.veraClient.getSandboxList(testAppInfo);
  t.true(Array.isArray(getSandboxListResult), 'Should be an array of values');

  if (getSandboxListResult.length > 0) {
    let buildLocated = false;
    t.truthy(getSandboxListResult[0]._attributes.sandbox_id, 'Elements of array should include sandbox_id attribute');

    // Only look for scans in sanboxes - promoted scans would be created manually, so not in scope of the test
    for (const sandbox of getSandboxListResult) {
      // Get list of builds for each sandbox and test getBuildList()
      const sandboxBuildList = await t.context.veraClient.getBuildList({appId: testAppInfo.appId, sandboxId: sandbox._attributes.sandbox_id});
      t.true(Array.isArray(sandboxBuildList), 'Should be an array of values');

      if (sandboxBuildList.length > 0) {
        t.truthy(sandboxBuildList[0]._attributes.build_id, 'Elements of array should include sandbox_id attribute');
        for (const sandboxBuild of sandboxBuildList) {
          try {
            const detailedReportResult = await t.context.veraClient.detailedReport({buildId: sandboxBuild._attributes.build_id});
            buildLocated = true;
            t.truthy(detailedReportResult['flaw-status'], 'Report should contain a flaw-status field');
          } catch (error) {
            // This will be kept here for debugging purposes. The message below, if enabled, should be extremely rare to see
            // console.log('Located build:', sandboxBuild._attributes.build_id, 'Status: ', error.message);
          } //
        } //    ~o/  _o
      } //      /|    |\
    } //        / \  / >

    if (!buildLocated) {
      console.log('Some tests skipped: No builds with finished scans found. It may take several hours for a scan started by this test run to complete');
    }
  } else {
    console.log('Some tests skipped: No sandboxes found. Next time this test runs, some sandboxes should be available');
  }
});

const fs = require("fs");
const path = require("path");

const jspath = require("jspath");
const moment = require("moment");
const tempy = require("tempy");

const VeracodeClient = require("../src/VeracodeClient");

// Something unique for each build of this repository
// Unix ms timestamp is unique enough
const somethingUnique = moment().format("x");
const timeout = 60000;

const testApp = {
  appName: "veracode-client-test",
  appVersion: `test-version-${somethingUnique}`,
  sandboxName: `test-sandbox-${somethingUnique}`,
  businessCriticality: "High", // 'High' is used by security-scan, so using it here as well
  teams: "Security", // Only security team will get notifications about this test app
  autoScan: true, // Required to start scan automatically after pre-scan
  description: "This application is used to test veracode-client",
};

const veraClient = new VeracodeClient(process.env.VERA_ID, process.env.VERA_KEY);

// Ensure test application is created
beforeAll(async () => {
  // Get applications list
  const getAppListResult = await veraClient.getAppList();
  expect(getAppListResult).toBeInstanceOf(Array);

  // This is not a case only when there is no apps at Veracode at all - very unlikely scenario, and is fixed after 1st run
  if (getAppListResult.length > 0) {
    expect(getAppListResult[0]._attributes.app_name).toBeDefined();
    expect(getAppListResult[0]._attributes.app_id).toBeDefined();
    expect(getAppListResult[0]._attributes.app_id).not.toBeNaN();
  }

  // Locate the test app or create it if needed
  const searchResult = jspath.apply(
    `._attributes{.app_name === "${testApp.appName}"}.app_id`,
    getAppListResult
  );

  // We want to know if there is a scenario when search for an application returns more than 1 app_id
  expect(searchResult.length).toBeLessThanOrEqual(1);

  if (searchResult.length > 0) {
    console.log("Test application was located under Application ID", searchResult[0]);
    testApp.appId = searchResult[0];
  } else {
    console.log(`Test application '${testApp.appName}' was not found in Veracode. It will be created...`);
    const createAppResult = await veraClient.createApp(testApp);
    testApp.appId = createAppResult.application._attributes.app_id;
  }
}, timeout);

// All tests working with veracode API directly are serial - it does not handle async load well
test("Create and delete a temp app", async () => {
  const tempAppInfo = {
    appName: `veracode-client-temp-${somethingUnique}`,
    businessCriticality: "Low",
    description: "This application is used in veracode-client unit tests. It's safe to remove it",
  };

  // Create a temp application
  const createAppResult = await veraClient.createApp(tempAppInfo);
  expect(createAppResult.application._attributes.app_id).toBeDefined();
  expect(createAppResult.application._attributes.app_id).not.toBeNaN();
  // Should not allow creation of another application with the same name
  await expect(veraClient.createApp(tempAppInfo)).rejects.toThrow();
  tempAppInfo.appId = createAppResult.application._attributes.app_id;

  // Delete temp application
  const deleteAppResult = await veraClient.deleteApp(tempAppInfo);
  expect(deleteAppResult).toBeInstanceOf(Array);
}, timeout);

test("Create and start a new static scan", async () => {
  const testAppInfo = { ...testApp };

  // Create a new sandbox
  const createSandboxResult = await veraClient.createSandbox(testAppInfo);
  expect(createSandboxResult.sandbox._attributes.sandbox_id).toBeDefined();
  testAppInfo.sandboxId = createSandboxResult.sandbox._attributes.sandbox_id;

  // Create a new build - allows to explicitly mark a new scan with application version
  const createBuildResult = await veraClient.createBuild(testAppInfo);
  expect(createBuildResult.build._attributes.build_id).toBeDefined();
  expect(createBuildResult._attributes.sandbox_id).toBeDefined();
  expect(createBuildResult.build._attributes.build_id).not.toBeNaN();
  testAppInfo.buildId = createBuildResult.build._attributes.build_id;

  // Create ZIP archive
  const targetDir = path.resolve(__dirname, "../src"); // just give it something small
  testAppInfo.file = tempy.file({ name: `${testAppInfo.appVersion}.zip` });
  try {
    await veraClient.createZipArchive(targetDir, testAppInfo.file, ["node_modules/**/*"]);
    expect(fs.existsSync(testAppInfo.file, "Should create a ZIP archive")).toBeTruthy();

    // Upload ZIP archive to Veracode
    const uploadResult = await veraClient.uploadFile(testAppInfo);
    expect(uploadResult.file._attributes.file_id).toBeDefined();
    testAppInfo.file_id = uploadResult.file._attributes.file_id;

    // Start static scan
    const beginPrescanResult = await veraClient.beginPrescan(testAppInfo);
    expect(beginPrescanResult.build.analysis_unit._attributes.status).toBeDefined();

    // Test detailedReport error - duplicated here in a hope that will be
    // running in parallel some day. Report for this test app is not yet
    // available, so we expect a specific error here
    expect(veraClient.detailedReport(testAppInfo)).rejects.toThrow("No report available.");
  } finally {
    // Delete ZIP archive
    fs.unlinkSync(testAppInfo.file);
  }
}, timeout);

test("Get list of builds for all applications", async () => {
  const getAppBuilds = await veraClient.getAppBuilds({ includeInProgress: true });
  expect(getAppBuilds).toBeInstanceOf(Array);
  expect(getAppBuilds[0]._attributes.modified_date).toBeDefined();
}, timeout);

// Scans take anything from 2-4+ hours, so using a previously completed scan
test("Get report for a previous scan", async () => {
  const testAppInfo = { ...testApp };

  // Go through each previous build in all sandboxes and search for a completed scan
  const getSandboxListResult = await veraClient.getSandboxList(testAppInfo);
  expect(getSandboxListResult).toBeInstanceOf(Array);

  if (getSandboxListResult.length > 0) {
    let buildLocated = false;
    expect(getSandboxListResult[0]._attributes.sandbox_id).toBeDefined();

    // Only look for scans in sanboxes - promoted scans would be created manually, so not in scope of the test
    for (const sandbox of getSandboxListResult) {
      // Get list of builds for each sandbox and test getBuildList()
      const sandboxBuildList = await veraClient.getBuildList({ appId: testAppInfo.appId, sandboxId: sandbox._attributes.sandbox_id });
      expect(sandboxBuildList).toBeInstanceOf(Array);

      if (sandboxBuildList.length > 0) {
        expect(sandboxBuildList[0]._attributes.build_id).toBeDefined();
        for (const sandboxBuild of sandboxBuildList) {
          try {
            const detailedReportResult = await veraClient.detailedReport({ buildId: sandboxBuild._attributes.build_id });
            buildLocated = true;
            expect(detailedReportResult["flaw-status"]).toBeDefined();
          } catch (error) {
            // This will be kept here for debugging purposes. The message below, if enabled, should be extremely rare to see
            // console.log('Located build:', sandboxBuild._attributes.build_id, 'Status: ', error.message);
          } //
        } //    ~o/  _o
      } //      /|    |\
    } //        / \  / >

    if (!buildLocated) {
      console.log("Some tests skipped: No builds with finished scans found. It may take several hours for a scan started by this test run to complete");
    }
  } else {
    console.log("Some tests skipped: No sandboxes found. Next time this test runs, some sandboxes should be available");
  }
}, timeout);

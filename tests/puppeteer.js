const puppeteer = require("puppeteer");
require("../app");
const { seed_db, testUserPassword } = require("../utils/seed_db");
const Job = require("../models/Job");
const get_chai = require("../utils/get_chai");

let testUser = null;
let testJob = null;

let page = null;
let browser = null;

function myDelay_ms(time_ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, time_ms);
  });
}

// Launch the browser and open a new blank page
describe("jobs-ejs puppeteer test", function () {
  before(async function () {
    this.timeout(10000);
    //await sleeper(5000)
    browser = await puppeteer.launch({ headless: false, slowMo: 100 });
    page = await browser.newPage();
    await page.goto("http://localhost:3000");
  });
  after(async function () {
    this.timeout(5000);
    await browser.close();
  });
  describe("got to site", function () {
    it("should have completed a connection", async function () {});
  });
  describe("index page test", function () {
    this.timeout(10000);
    it("finds the index page logon link", async () => {
      this.logonLink = await page.waitForSelector(
        "a ::-p-text(Click this link to logon)"
      );
    });
    it("gets to the logon page", async () => {
      await this.logonLink.click();
      await page.waitForNavigation();
      const email = await page.waitForSelector('input[name="email"]');
    });
  });
  describe("logon page test", function () {
    this.timeout(20000);
    it("resolves all the fields", async () => {
      this.email = await page.waitForSelector('input[name="email"]');
      this.password = await page.waitForSelector('input[name="password"]');
      this.submit = await page.waitForSelector("button ::-p-text(Logon)");
    });
    it("sends the logon", async () => {
      testUser = await seed_db();
      await this.email.type(testUser.email);
      await this.password.type(testUserPassword);
      await this.submit.click();
      await page.waitForNavigation();
      await page.waitForSelector(`p ::-p-text(${testUser.name} is logged on.)`);
      await page.waitForSelector("a ::-p-text(change the secret)");
      await page.waitForSelector('a[href="/secretWord"]');
      const copyr = await page.waitForSelector("p ::-p-text(copyright)");
      const copyrText = await copyr.evaluate((el) => el.textContent);
      console.log("copyright text: ", copyrText);
    });
  });

  describe("puppeteer job operations", function () {
    this.timeout(20000);

    it("Find the jobs page link", async () => {
      this.jobsLink = await page.waitForSelector(
        "a ::-p-text(change the jobs)"
      );
    });

    it("Get to the jobs page", async () => {
      const { expect } = await get_chai();

      await this.jobsLink.click({ delay: 1500 });
      await page.waitForNavigation();

      // header ejs
      await page.waitForSelector(`p ::-p-text(${testUser.name} is logged on.)`);

      const pageContent = await page.content();
      // console.log(pageContent);

      // footer ejs
      const copyr = await page.waitForSelector("p ::-p-text(copyright)");
      const copyrText = await copyr.evaluate((el) => el.textContent);
      console.log("copyright text: ", copyrText);

      //
      expect(pageContent).to.include("Jobs List");
      expect(pageContent).to.include(testUser.name);
    });

    it("Find the Add new job link", async () => {
      this.newJobLink = await page.waitForSelector(
        "button ::-p-text(Add new job)"
      );
    });

    it("Get to Add A Job page", async () => {
      const { expect } = await get_chai();

      newJob = await factory.build("job");
      console.log("New Job data - newJob = ", newJob);

      await this.newJobLink.click({ delay: 2000 });
      await page.waitForNavigation();

      // header ejs
      await page.waitForSelector(`p ::-p-text(${testUser.name} is logged on.)`);

      const pageContent = await page.content();

      expect(pageContent).to.include("Create New Job");

      this.company = await page.waitForSelector('input[name="company"]');
      this.position = await page.waitForSelector('input[name="position"]');

      this.createButton = await page.waitForSelector(
        "button ::-p-text(Create)"
      );
      myDelay_ms(1000);
    });

    it("Create New Job!", async () => {
      await this.company.type(newJob.company);
      await this.position.type(newJob.position);

      await page.select("select#status", newJob.status);

      myDelay_ms(1000);

      await this.createButton.click({ delay: 1500 });
      await page.waitForNavigation();

      const pageContent = await page.content();

      await page.waitForSelector(`p ::-p-text(${testUser.name} is logged on.)`);

      const jobs = await Job.find({ createdBy: testUser._id });

      myDelay_ms(1000);
    });
  });

  describe("Job delete", function () {
    this.timeout(20000);

    it("Randomly delete an entry: ", async function () {
      let deleteBtns = await page.$$("button ::-p-text(Delete)");

      await deleteBtns[Math.floor(deleteBtns.length * Math.random())].click({
        delay: 2000,
      });

      await page.waitForSelector(`p ::-p-text(${testUser.name} is logged on.)`);

      const pageContent = await page.content();

      await myDelay_ms(4000);
    });
  });
});

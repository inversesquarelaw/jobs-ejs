const express = require("express");
const router = express.Router();

const {
  getAllJobs,
  editJob,
  updateJob,
  addJob,
  createJob,
  deleteJob,
} = require("../controllers/jobs");

router.get("/", getAllJobs);

router.get("/edit/:id", editJob);

router.post("/update/:id", updateJob);

router.get("/newJob", addJob);

router.post("/newJob", createJob);

router.post("/delete/:id", deleteJob);

router.get("/");

module.exports = router;

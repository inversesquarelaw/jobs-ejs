const Job = require("../models/Job");

const getAllJobs = async (req, res) => {
  try {
    const jobs = await Job.find({ createdBy: req.user._id.toString() });
    res.render("jobs", { jobs });
  } catch {
    req.flash("error", "Could not get all jobs.");
    res.redirect("/");
  }
};

const editJob = async (req, res) => {
  const job = await Job.findById(req.params.id, req.body);
  if (!job) {
    req.flash("error", "That specific job does not exist.");
    res.redirect("/jobs");
  } else {
    res.render("job", { job });
  }
};

const updateJob = async (req, res, next) => {
  const job = await Job.findByIdAndUpdate(req.params.id, req.body);
  req.flash("info", "Job has been updated.");
  res.redirect("/jobs");
};

const addJob = async (req, res) => {
  res.render("newJob", { job: null });
};

const createJob = async (req, res, next) => {
  req.body.createdBy = req.user._id;
  const job = await Job.create(req.body);
  if (!job) {
    req.flash("error", "Job could not be created");
    res.redirect("/jobs");
  } else {
    req.flash("info", "The job entry was created.");
    res.redirect("/jobs");
  }
};

const deleteJob = async (req, res, next) => {
  try {
    const job = await Job.findOneAndDelete({
      createdBy: req.user._id,
      _id: req.params.id,
    });
    req.flash("info", "The job entry was deleted.");
    res.redirect("/jobs");
  } catch {
    req.flash("error", "An error has occurred. Please try again.");
  }
};

module.exports = {
  getAllJobs,
  editJob,
  updateJob,
  addJob,
  createJob,
  deleteJob,
};

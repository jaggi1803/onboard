const mongoose = require("mongoose");

mongoose.connect(process.env.mongo_url);
const connectionResult = mongoose.connection;

connectionResult.on("error", () => {
  console.log("connection error:");
});
connectionResult.on("connected", () => {
  console.log("MongoDB connected successfully");
});

module.exports = connectionResult;

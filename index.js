const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { connectDB } = require("./config/db");

// Import Routes
const paymentRoutes = require("./routes/paymentRoutes");
const statsRoutes = require("./routes/statsRoutes");
const reviewRoutes = require("./routes/reviewRoutes");
const favoriteRoutes = require("./routes/favoriteRoutes");
const userRoutes = require("./routes/userRoutes");
const mealRoutes = require("./routes/mealRoutes");
const orderRoutes = require("./routes/orderRoutes");
const blogRoutes = require("./routes/blogRoutes");
const requestRoutes = require("./routes/requestRoutes");
const complaintRoutes = require("./routes/complaintRoutes");
const subscriberRoutes = require("./routes/subscriberRoutes");

const app = express();
const port = process.env.PORT || 3000;

// middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://local-chef-bazaar.web.app",
    "https://local-chef-bazaar-client.vercel.app"
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

// Connect to Database
connectDB();

// Use Routes
app.use("/", paymentRoutes);
app.use("/", statsRoutes);
app.use("/", reviewRoutes);
app.use("/", favoriteRoutes);
app.use("/", userRoutes);
app.use("/", mealRoutes);
app.use("/", orderRoutes);
app.use("/", blogRoutes);
app.use("/", requestRoutes);
app.use("/", complaintRoutes);
app.use("/", subscriberRoutes);

app.get("/", (req, res) => {
  res.send("LocalChefBazaar Server is Running 🚀 (Modular Architecture)");
});

// listening the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;

const dotenv = require("dotenv")
dotenv.config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const axios = require('axios');
const { OpenAIApi } = require("openai");
const readline = require("readline");
const { type } = require("os");



const API_KEY = process.env.OPENAI_API_KEY;
console.log("api key",API_KEY)

// Initialize conversation history
let conversationHistory = [
  {
      role: "system",
      content: `You are a professional medical summarization assistant. Your role is to summarize user-provided experiences into concise, clear, and medically relevant summaries. The summaries should focus on key symptoms, emotions, behaviors, and any notable medical or psychological details mentioned by the user.

Guidelines:
1. Extract the most important details from the text and organize them in a coherent, logical order.
2. Avoid including unnecessary conversational details or filler words.
3. If the text contains medical or psychological terminology, ensure accurate and professional phrasing.
4. Structure the summary in a way that is easy for healthcare professionals to understand.
5. Keep the summary under [desired word limit, e.g., 100 words], unless the input text requires more detail to be precise.
6. Provide a professional tone and avoid speculation or assumptions beyond what is stated.

Example Input:
"I've been feeling really anxious lately. My heart races when I think about work, and I've been getting these headaches almost every day. I tried sleeping more, but it doesn't seem to help much. I also feel like my appetite is gone, and I just don't enjoy eating anymore. I don't know what's wrong."

Example Summary:
"The user reports experiencing persistent anxiety with symptoms including racing heart, daily headaches, reduced appetite, and loss of enjoyment in eating. Sleep adjustments have not alleviated these symptoms. The user is seeking insight into potential causes.`,
  },
];



async function chatWithGPT(prompt) {
  try {
      // Add user input to conversation history
      conversationHistory.push({ role: "user", content: prompt });

      // Send request to OpenAI API
      const response = await axios.post(
          "https://api.openai.com/v1/chat/completions",
          {
              model: "gpt-4o-mini", // Adjust the model as needed
              messages: conversationHistory,
          },
          {
              headers: {
                  Authorization: `Bearer ${API_KEY}`, // Ensure your API key is securely set
                  "Content-Type": "application/json",
              },
          }
      );

      // Extract assistant's response
      const assistantResponse = response.data.choices[0].message.content;

      // Add assistant response to conversation history
      conversationHistory.push({ role: "assistant", content: assistantResponse });

      return assistantResponse;
  } catch (error) {
      // Handle errors gracefully
      console.error("Error with OpenAI API:", error.response?.data || error.message);

      // Return an error message for the user
      return "I'm sorry, but there was an error processing your request. Please try again.";
  }
}



// Database Connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

// User Schema and Model
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  name: {
    type: String,
    required: true,
  },
  isFirstLogin:{
     type:Boolean,
     default:false
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 8);
  }
  next();
});

// Compare passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// Middleware for Token Authentication
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", ""); // Extract token

    if (!token) {
      return res
        .status(401)
        .json({ message: "No auth token found. Please log in." });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    req.user = { userId: user._id, email: user.email, name: user.name }; // Attach user info to the request object
    next();
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Invalid or expired token. Please log in again." });
  }
};

// Global Error Handler Middleware
const errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode).json({
    message: err.message,
    stack: process.env.NODE_ENV === "production" ? null : err.stack,
  });
};

// Express App Setup
const app = express();

app.use(cors());
app.use(express.json());
// Connect to MongoDB
connectDB();

// Registration Endpoint
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    const user = new User({ email, password, name });
    await user.save();
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "1d" }
    );
    res
      .status(201)
      .json({
        token,
        user: { id: user._id, email: user.email, name: user.name },
      });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error registering user. Please try again later." });
  }
});

// Login Endpoint
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password!" });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password!" });
    }
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.json({
      token,
      user: { id: user._id, email: user.email, name: user.name },
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error logging in. Please try again later." });
  }
});

// Get Current User Endpoint (Protected)
app.get("/auth/me", auth, async (req, res) => {
  try {
    // User data already attached in the middleware
    res.json(req.user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching user data. Please try again later." });
  }
});



//onboarding question
const onboardingQuestionSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true, // Email of the user
  },
  responses: [
    {
      question: { type: String, required: true },
      answer: { type: String, required: true },
    },
  ],
  createdAt: { type: Date, default: Date.now },
});

// Specify the collection name as "onboardingquestions"
const OnboardingQuestion = mongoose.model(
  "OnboardingQuestion",
  onboardingQuestionSchema,
  "onboardingquestions"
);

// Save Answers Endpoint
app.post("/api/save-answers", auth, async (req, res) => {
  try {
    const { responses } = req.body;

    // Validate the responses array
    if (!responses || !Array.isArray(responses)) {
      return res
        .status(400)
        .json({ message: "Responses are required and must be an array." });
    }

    // Save the answers with the user's email
    const newAnswers = new OnboardingQuestion({
      email: req.user.email, // Extract email from the authenticated user
      responses,
    });

    await newAnswers.save();

    res
      .status(201)
      .json({ message: "Answers saved successfully!", data: newAnswers });
  } catch (error) {
    console.error("Error saving answers:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const journalSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true, // Email of the user
  },
  medicine: {
    type: String,
    required: true, // Selected or custom medicine
  },
  intention: {
    type: String,
    required: true, // Selected or custom intention
  },
  experienceDate: {
    type: String, // Save the date as a string in "YYYY-MM-DD" format
    required: true,
  },
  currentState: {
    type: String,
     // Current state of mind
  },
  postExperience: {
    type: String,
    // Post-experience outlook
  },
  createdAt: {
    type: Date,
    default: Date.now, // Timestamp of journal entry creation
  },
});

const Journal = mongoose.model("Journal", journalSchema);

// Save Journal Entry// Save Journal Entry
app.post("/api/journal", auth, async (req, res) => {
  console.log(req.body.journalEntry)
  try {
    const {
      medicine,
      intention,
      experienceDate,
      currentState,
      postExperience,
    } = req.body.journalEntry;

    // Validate required fields
    if (
      !medicine ||
      !intention ||
      !experienceDate
    ) {
      return res.status(400).json({ message: "All fields are required." });
    }

    // Ensure experienceDate is a valid date
    // console.log(experienceDate,"experiencdata")
    const date = new Date(experienceDate);
   
    if (isNaN(date.getTime())) {
      return res.status(400).json({ message: "Invalid experience date." });
    }

    // Format the date as "YYYY-MM-DD"
    const formattedDate = date.toISOString().split("T")[0];

    // Create a new journal entry
    const newJournal = new Journal({
      email: req.user.email, // Extracted from authenticated user (via auth middleware)
      medicine,
      intention,
      experienceDate: formattedDate, // Save formatted date
      currentState,
      postExperience,
    });

    // Save the journal entry to the database
    await newJournal.save();

    res
      .status(201)
      .json({ message: "Journal entry saved successfully!", data: newJournal });
  } catch (error) {
    console.error("Error saving journal entry:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// MuscleSelection Schema
const muscleSelectionSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true, // Email of the user
  },
  date:{
    type:String,
    required:true,
  },
  selectedMuscles: {
    type: [String], // Array of muscle names
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Model for MuscleSelection
const MuscleSelection = mongoose.model(
  "MuscleSelection",
  muscleSelectionSchema
);

// Define valid muscles
const validMuscles = [
  "CHEST",
  "OBLIQUES",
  "ABS",
  "BICEPS",
  "TRICEPS",
  "NECK",
  "FRONT_DELTOIDS",
  "HEAD",
  "ABDUCTORS",
  "QUADRICEPS",
  "KNEES",
  "CALVES",
  "FOREARM",
  "TRAPEZIUS",
  "BACK_DELTOIDS",
  "UPPER_BACK",
  "LOWER_BACK",
  "GLUTEAL",
  "HAMSTRING",
  "LEFT_SOLEUS",
  "RIGHT_SOLEUS",
];

app.post("/api/save-muscles", auth, async (req, res) => {
  try {
    const { selectedMuscles } = req.body;

    // Validate muscles input
    if (!selectedMuscles || !Array.isArray(selectedMuscles)) {
      return res
        .status(400)
        .json({ message: "Selected muscles must be an array." });
    }

    // Clean up and validate the selected muscles
    const cleanedMuscles = selectedMuscles.map((muscle) =>
      muscle.trim().toUpperCase()
    );
    const invalidMuscles = cleanedMuscles.filter(
      (muscle) => !validMuscles.includes(muscle)
    );

    if (invalidMuscles.length > 0) {
      return res
        .status(400)
        .json({ message: `Invalid muscles: ${invalidMuscles.join(", ")}` });
    }

    // Ensure user email is set in req.user (from auth middleware)
    if (!req.user || !req.user.email) {
      return res
        .status(400)
        .json({ message: "User not authenticated. Please log in." });
    }

    

    
      // Create a new muscle selection record if not found
      muscleSelection = new MuscleSelection({
        email: req.user.email,
        date:req.body.date,
        selectedMuscles: cleanedMuscles,
      });
 

    // Save or update the muscle selection record
    await muscleSelection.save();

    res
      .status(201)
      .json({ message: "Muscles saved successfully!", data: muscleSelection });
  } catch (error) {
    console.error("Error saving muscles:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const journeySchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  date:{
    type:String,
    required:true
  },
  
  levels: [
    {
      title: {
        type: String,
        required: true,
      },
      questionAnswers: [
        {
          question: {
            type: String,
            required: true,
          },
          answer: {
            type: String,
            required: true,
          },
        },
      ],
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Journey = mongoose.model("Journey", journeySchema);

app.post("/api/story-answers", async (req, res) => {
  try {
    console.log(req.body)
    const { email,date, levels } = req.body;

    // Create a new journey with the provided email and levels
    const newJourney = new Journey({
      email,
      date,
      levels,
    });

    await newJourney.save();

    res
      .status(201)
      .json({ message: "Journey saved successfully!", data: newJourney });
  } catch (error) {
    console.error("Error saving journey:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});



//post experience
const expSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true, // Email of the user
  },
  date:{
    type:String,
    required:true,
  },
  postExperience: {
    type: String,
  },
  createdAt: {
    type: Date,
    default: Date.now, // Timestamp of journal entry creation
  },
});

const PostExperience = mongoose.model("PostExperience", expSchema);

// Save Journal Entry// Save Journal Entry
app.post("/api/savePostExperience", auth, async (req, res) => {
  try {
    const {
      postExperience
    } = req.body.journalEntry;    
    // Create a new journal entry
    const newJournal = new PostExperience({
      email: req.user.email,
      date:req.body.date,
      postExperience:postExperience,
    });

    // Save the journal entry to the database
    await newJournal.save();

    res
      .status(201)
      .json({ message: "Journal entry saved successfully!", data: newJournal });
  } catch (error) {
    console.error("Error saving journal entry:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
//audio record
const audioSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true, // Email of the user
  },
  date:{
    type:String,
    required:true,
  },
  audio: {
    type: String, // Post-experience outlook
  },
  createdAt: {
    type: Date,
    default: Date.now, // Timestamp of journal entry creation
  },
});

const Audio = mongoose.model("Audio", audioSchema);

app.post("/api/saveAudio", auth, async (req, res) => {
  try {
    // Extract the postExperience from the body directly
    const { postExperience } = req.body;  // Access directly from the body (not journalEntry.postExperience)

    const response = await chatWithGPT(postExperience);
    console.log("GPT:", response);
    // Validate required fields
    // if (!postExperience) {
    //   return res.status(400).json({ message: "All fields are required." });
    // }

    // Create a new Audio entry
    const newAudio = new Audio({
      email: req.user.email,  // Extracted from the authenticated user (via auth middleware)
      date:req.body.date,
      audio: response,  // Save the postExperience as 'audio'
    });

    // Save the journal entry to the database
    await newAudio.save();

    res.status(201).json({ message: "Audio entry saved successfully!", data: newAudio });
  } catch (error) {
    console.error("Error saving audio entry:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});



app.post("/api/profile", auth, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    // Fetch user data
    const user = await User.findOne({ email }).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Fetch the last onboarding question
    const onboardingQuestion = await OnboardingQuestion.findOne({ email })
      .sort({ createdAt: -1 }); // Sort by 'createdAt' in descending order
      
      
    // Fetch additional data from other collections
    const journals = await Journal.findOne({ email }).sort({ createdAt: -1 });
    const muscleSelections = await MuscleSelection.findOne({ email }).sort({ createdAt: -1 });
    const journeys = await Journey.findOne({ email }).sort({ createdAt: -1 });
    const postExperiences = await PostExperience.findOne({ email }).sort({ createdAt: -1 });
    const audios = await Audio.findOne({ email }).sort({ createdAt: -1 });


    const muscleSelectionsAll = await MuscleSelection.find({ email });
    const journeysAll = await Journey.find({ email });
    const postExperiencesAll = await PostExperience.find({ email });
    const audiosAll = await Audio.find({ email });
    const journalAllData = await Journal.find({ email });
    console.log(journalAllData)
    const dates = journalAllData.map((journal) => journal.experienceDate);
    // Aggregate all data
    const profileData = {
      user,
      dates,
      journalAllData,
      onboardingQuestion, // Last document
      journals,
      muscleSelections,
      journeys,
      postExperiences,
      audios,
      muscleSelectionsAll,
      journeysAll,
      postExperiencesAll,
      audiosAll
    };

    res.status(200).json({
      message: "Profile data fetched successfully",
      data: profileData,
    });
  } catch (error) {
    console.error("Error fetching profile data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});





app.get("/",(req,res)=>{
  res.send("hello ajay")
})
// Global Error Handler
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

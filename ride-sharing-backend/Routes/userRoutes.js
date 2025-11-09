const express = require("express");
const bcrypt = require("bcryptjs");
const Student = require("../Models/Students");
const Faculty = require("../Models/Faculty");
const Admin = require("../Models/Admin");
const verifyAuth = require("../middleware/authMiddleware");

const router = express.Router();

// Student registration
router.post("/students", async (req, res) => {
  try {
    const { fullName, email, rollNumber, course, department, password } =
      req.body;
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const newStudent = new Student({
      fullName,
      email,
      rollNumber,
      course,
      department,
      password: hashed,
    });

    const saved = await newStudent.save();
    res.status(201).json(saved);
  } catch (err) {
    console.error("Error registering student:", err);
    res
      .status(500)
      .json({ message: "Error registering student", error: err.message });
  }
});

// Faculty registration
router.post("/faculty", async (req, res) => {
  try {
    const { fullName, email, employeeId, department, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const newFaculty = new Faculty({
      fullName,
      email,
      employeeId,
      department,
      password: hashed,
    });

    const saved = await newFaculty.save();
    res.status(201).json(saved);
  } catch (err) {
    console.error("Error registering faculty:", err);
    res
      .status(500)
      .json({ message: "Error registering faculty", error: err.message });
  }
});

// Admin registration
router.post("/admin", async (req, res) => {
  try {
    const { fullName, email, staffId, role, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const newAdmin = new Admin({
      fullName,
      email,
      staffId,
      role,
      password: hashed,
    });

    const saved = await newAdmin.save();
    res.status(201).json(saved);
  } catch (err) {
    console.error("Error registering admin:", err);
    res
      .status(500)
      .json({ message: "Error registering admin", error: err.message });
  }
});

// --- Protected profile endpoints ---
// GET /api/user/me -> return current user's profile based on role
router.get("/me", verifyAuth, async (req, res) => {
  try {
    const { id, role } = req.user || {};
    if (!id)
      return res.status(400).json({ message: "Missing user id in token" });

    let Model = Student;
    if (role === "faculty") Model = Faculty;
    else if (role === "admin") Model = Admin;

    const user = await Model.findById(id).lean();
    if (!user) return res.status(404).json({ message: "User not found" });

    // Remove sensitive fields
    delete user.password;
    return res.json({ success: true, user });
  } catch (err) {
    console.error("Error fetching profile:", err);
    return res.status(500).json({ message: "Error fetching profile" });
  }
});

module.exports = router;

// GET requests for owner: fetch incoming join requests for the signed-in user
router.get("/requests", verifyAuth, async (req, res) => {
  try {
    const Request = require("../Models/Request");
    const userId = req.user?.id;
    if (!userId) return res.status(400).json({ message: "Missing user id" });

    // Match requests where toUserId equals userId OR toUserEmail equals user's email (covers older rides with no ownerId)
    const userEmail = req.user?.email;
    const requests = await Request.find({
      $or: [{ toUserId: userId }, { toUserEmail: userEmail }],
    }).sort({ createdAt: -1 });
    return res.json({ success: true, requests });
  } catch (err) {
    console.error("Error fetching requests:", err);
    return res.status(500).json({ message: "Error fetching requests" });
  }
});

// GET /api/user/requests/outgoing -> requests created by the signed-in user
router.get("/requests/outgoing", verifyAuth, async (req, res) => {
  try {
    const Request = require("../Models/Request");
    const userId = req.user?.id;
    if (!userId) return res.status(400).json({ message: "Missing user id" });

    const requests = await Request.find({ requesterId: userId }).sort({
      createdAt: -1,
    });
    return res.json({ success: true, requests });
  } catch (err) {
    console.error("Error fetching outgoing requests:", err);
    return res
      .status(500)
      .json({ message: "Error fetching outgoing requests" });
  }
});

// GET /api/user/accepted -> all accepted requests where user is owner or requester
router.get("/accepted", verifyAuth, async (req, res) => {
  try {
    const Request = require("../Models/Request");
    const userId = req.user?.id;
    const userEmail = req.user?.email;
    if (!userId) return res.status(400).json({ message: "Missing user id" });

    const requests = await Request.find({
      status: "accepted",
      $or: [
        { toUserId: userId },
        { requesterId: userId },
        { toUserEmail: userEmail },
      ],
    }).sort({ createdAt: -1 });
    return res.json({ success: true, requests });
  } catch (err) {
    console.error("Error fetching accepted requests:", err);
    return res
      .status(500)
      .json({ message: "Error fetching accepted requests" });
  }
});

// PATCH /api/user/requests/:id -> owner accepts or rejects a join request
router.patch("/requests/:id", verifyAuth, async (req, res) => {
  try {
    console.log("PATCH /api/user/requests/:id called", {
      params: req.params,
      user: req.user && { id: req.user.id, email: req.user.email },
    });
    const Request = require("../Models/Request");
    const Ride = require("../Models/Ride");
    const reqId = req.params.id;
    const { status } = req.body || {};

    if (!["accepted", "rejected"].includes(status)) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const requestDoc = await Request.findById(reqId);
    if (!requestDoc)
      return res.status(404).json({ message: "Request not found" });

    // Only the ride owner (toUserId) can change the status
    const userId = req.user?.id;
    if (!userId) return res.status(403).json({ message: "Not authorized" });
    // Allow if user is owner by id or by email
    const userEmail = req.user?.email;
    if (
      !(requestDoc.toUserId === userId || requestDoc.toUserEmail === userEmail)
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized to modify this request" });
    }

    // If accepting, ensure ride has available seats and decrement atomically
    if (status === "accepted") {
      if (!requestDoc.rideId) {
        return res
          .status(400)
          .json({ message: "Request has no ride attached" });
      }
      // Atomically decrement availableSeats only if > 0
      const updatedRide = await Ride.findOneAndUpdate(
        { _id: requestDoc.rideId, availableSeats: { $gt: 0 } },
        { $inc: { availableSeats: -1 } },
        { new: true }
      );
      if (!updatedRide) {
        return res.status(400).json({ message: "No seats available" });
      }
    }

    requestDoc.status = status;

    // When accepted, create a Chat between requester and owner (if not exists)
    if (status === "accepted") {
      try {
        const Chat = require("../Models/Chat");

        // If toUserId is missing but toUserEmail exists (older anonymous rides), try to resolve owner id now
        if (!requestDoc.toUserId && requestDoc.toUserEmail) {
          try {
            const Student = require("../Models/Students");
            const Faculty = require("../Models/Faculty");
            const Admin = require("../Models/Admin");
            const foundStudent = await Student.findOne({
              email: requestDoc.toUserEmail,
            });
            const foundFaculty = !foundStudent
              ? await Faculty.findOne({ email: requestDoc.toUserEmail })
              : null;
            const foundAdmin =
              !foundStudent && !foundFaculty
                ? await Admin.findOne({ email: requestDoc.toUserEmail })
                : null;
            const owner = foundStudent || foundFaculty || foundAdmin || null;
            if (owner) {
              requestDoc.toUserId = owner._id.toString();
            }
          } catch (lookupErr) {
            console.error(
              "Error resolving owner id from email during accept:",
              lookupErr
            );
          }
        }

        const participants = [requestDoc.requesterId, requestDoc.toUserId]
          .filter(Boolean)
          .map(String);
        let chat = null;
        if (participants.length === 2) {
          // try to find existing chat with same participants (both ways)
          chat = await Chat.findOne({
            participants: { $all: participants, $size: 2 },
          });
          if (!chat) {
            chat = await Chat.create({ participants });
          }
          requestDoc.chatId = chat._id.toString();

          // Notify participants via Socket.IO (if connected)
          try {
            const socketUtil = require("../utils/socket");
            const io = socketUtil.getIO();
            if (io) {
              // Notify by user rooms (user:<id>) so clients can show new accepted rides notification
              participants.forEach((p) => {
                try {
                  io.to("user:" + p).emit("chatCreated", {
                    chatId: chat._id.toString(),
                    participants,
                  });
                } catch (e) {}
              });
            }
          } catch (emitErr) {
            console.error("Error emitting chatCreated event:", emitErr);
          }
        }
      } catch (cErr) {
        console.error("Error creating chat for accepted request:", cErr);
      }
    }

    await requestDoc.save();

    return res.json({ success: true, request: requestDoc });
  } catch (err) {
    console.error("Error updating request status:", err);
    return res.status(500).json({ message: "Error updating request" });
  }
});

// PUT /api/user/me -> update allowed fields for current user
router.put("/me", verifyAuth, async (req, res) => {
  try {
    const { id, role } = req.user || {};
    if (!id)
      return res.status(400).json({ message: "Missing user id in token" });

    const updates = req.body || {};

    let Model = Student;
    if (role === "faculty") Model = Faculty;
    else if (role === "admin") Model = Admin;

    // Allowed fields per model (minimal whitelist)
    const allowed = [
      "fullName",
      "rollNumber",
      "course",
      "department",
      "employeeId",
      "staffId",
    ];
    const patch = {};
    Object.keys(updates).forEach((k) => {
      if (allowed.includes(k)) patch[k] = updates[k];
    });

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    const updated = await Model.findByIdAndUpdate(
      id,
      { $set: patch },
      { new: true }
    ).lean();
    if (!updated) return res.status(404).json({ message: "User not found" });
    delete updated.password;
    return res.json({ success: true, user: updated });
  } catch (err) {
    console.error("Error updating profile:", err);
    return res
      .status(500)
      .json({ message: "Error updating profile", error: err.message });
  }
});

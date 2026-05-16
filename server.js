// ============================================================
//  BLOOD DONATION SYSTEM — Node.js / Express Backend
//  File: server.js
//  Install: npm install express mssql bcryptjs jsonwebtoken
//           nodemailer cors dotenv express-validator
// ============================================================

require("dotenv").config();
const express       = require("express");
const sql           = require("mssql");
const bcrypt        = require("bcryptjs");
const jwt           = require("jsonwebtoken");
const nodemailer    = require("nodemailer");
const cors          = require("cors");
const { body, validationResult } = require("express-validator");

const app  = express();
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader("ngrok-skip-browser-warning", "true");
  next();
});

// ── HEALTH CHECK ──
app.get("/", (req, res) => {
  res.json({ status: "🩸 BloodLink API is running!", time: new Date() });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", db: pool ? "connected" : "disconnected" });
});

// ──────────────────────────────────────────────────────────────
// SQL SERVER CONFIG & AUTO-MIGRATION
// ──────────────────────────────────────────────────────────────
const dbConfig = {
  user:     process.env.DB_USER     || "sa",
  password: process.env.DB_PASSWORD || "1234",
  server:   process.env.DB_SERVER   || "localhost",
  database: process.env.DB_NAME     || "BloodDonationDB",
  port:     parseInt(process.env.DB_PORT) || 1433,
  options:  { encrypt: false, trustServerCertificate: true },
  pool:     { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

let pool;
(async () => {
  try {
    pool = await sql.connect(dbConfig);
    console.log("✅  SQL Server connected");

    // 👉 AUTO-MIGRATOR: Automatically adds 'IsBlocked' columns if they don't exist yet!
    await pool.request().query(`
      IF COL_LENGTH('Donors', 'IsBlocked') IS NULL
      BEGIN
          ALTER TABLE Donors ADD IsBlocked BIT DEFAULT 0 NOT NULL;
      END
      IF COL_LENGTH('Recipients', 'IsBlocked') IS NULL
      BEGIN
          ALTER TABLE Recipients ADD IsBlocked BIT DEFAULT 0 NOT NULL;
      END
    `);
    console.log("✅  Database schema verified (IsBlocked active)");

  } catch (err) {
    console.error("❌ DB Connection failed:", err.message);
  }
})();

// ──────────────────────────────────────────────────────────────
// EMAIL TRANSPORT
// ──────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  },
  tls: { rejectUnauthorized: false }
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({ from: process.env.MAIL_USER, to, subject, html });
    console.log("✅ Email sent to:", to);
    return true;
  } catch (e) {
    console.error("❌ Email error:", e.message);
    return false;
  }
}

// ──────────────────────────────────────────────────────────────
// JWT MIDDLEWARE
// ──────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || "blood_donation_secret_key_2024";

function authMiddleware(role) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token provided" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role && decoded.role !== "admin")
        return res.status(403).json({ error: "Access denied" });
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ──────────────────────────────────────────────────────────────
// ════════════════  PASSWORD RESET ROUTES  ════════════════
// ──────────────────────────────────────────────────────────────

app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    let userType = null;
    let userId = null;
    let userName = "";

    const donorCheck = await pool.request().input("email", sql.NVarChar, email).query("SELECT DonorID, FullName FROM Donors WHERE Email = @email");
    if (donorCheck.recordset.length > 0) {
      userType = "Donor"; userId = donorCheck.recordset[0].DonorID; userName = donorCheck.recordset[0].FullName;
    } else {
      const recCheck = await pool.request().input("email", sql.NVarChar, email).query("SELECT RecipientID, FullName FROM Recipients WHERE Email = @email");
      if (recCheck.recordset.length > 0) {
        userType = "Recipient"; userId = recCheck.recordset[0].RecipientID; userName = recCheck.recordset[0].FullName;
      }
    }

    if (!userType) return res.status(404).json({ error: "No account found with this email." });

    const resetToken = jwt.sign({ id: userId, email: email, role: userType.toLowerCase(), purpose: "reset" }, JWT_SECRET, { expiresIn: "15m" });
    const resetURL = `${process.env.FRONTEND_URL || "http://localhost:3000"}/reset-password?token=${resetToken}`;

    await sendEmail(email, "Password Reset Request - BloodLink", `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;">
        <h3>Hi ${userName},</h3>
        <p>You requested a password reset for your ${userType} account.</p>
        <p>Click the link below to set a new password. This link expires in 15 minutes.</p>
        <a href="${resetURL}" style="background:#dc2626;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;margin-top:10px;">Reset My Password</a>
        <p style="margin-top: 20px; font-size: 12px; color: #888;">If you did not request this, please ignore this email.</p>
      </div>
    `);

    res.json({ message: "Password reset link sent to your email." });
  } catch (err) {
    res.status(500).json({ error: "Server error during password reset request." });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.purpose !== "reset") return res.status(400).json({ error: "Invalid token purpose." });

    const hash = await bcrypt.hash(newPassword, 12);
    const table = decoded.role === "donor" ? "Donors" : "Recipients";
    const idField = decoded.role === "donor" ? "DonorID" : "RecipientID";

    await pool.request()
      .input("id", sql.Int, decoded.id)
      .input("hash", sql.NVarChar, hash)
      .query(`UPDATE ${table} SET PasswordHash = @hash WHERE ${idField} = @id`);

    res.json({ message: "Password updated successfully. You can now log in." });
  } catch (err) {
    res.status(401).json({ error: "Reset link is invalid or has expired." });
  }
});

// ──────────────────────────────────────────────────────────────
// ════════════════  ADMIN ROUTES  ════════════════
// ──────────────────────────────────────────────────────────────

app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  // Default Admin Credentials
  if (email === "admin@bloodlink.com" && password === "admin123") {
    const token = jwt.sign({ id: 999, email: email, role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, admin: { FullName: "System Admin", Email: email, role: "admin" } });
  } else {
    res.status(401).json({ error: "Invalid admin credentials" });
  }
});

app.get("/api/admin/donors", authMiddleware("admin"), async (req, res) => {
  try {
    const result = await pool.request().query(`SELECT DonorID, FullName, Email, Phone, BloodGroup, City, IsAvailable, IsBlocked, CreatedAt FROM Donors ORDER BY CreatedAt DESC`);
    res.json(result.recordset);
  } catch (err) { res.status(500).json({ error: "Server error fetching donors" }); }
});

app.get("/api/admin/recipients", authMiddleware("admin"), async (req, res) => {
  try {
    const result = await pool.request().query(`SELECT RecipientID, FullName, Email, Phone, BloodGroup, City, IsBlocked, CreatedAt FROM Recipients ORDER BY CreatedAt DESC`);
    res.json(result.recordset);
  } catch (err) { res.status(500).json({ error: "Server error fetching recipients" }); }
});

// 👉 NEW: Admin route to block/unblock a user
app.put("/api/admin/toggle-block", authMiddleware("admin"), async (req, res) => {
  const { id, type, isBlocked } = req.body; 
  const table = type === 'donor' ? 'Donors' : 'Recipients';
  const idField = type === 'donor' ? 'DonorID' : 'RecipientID';
  
  try {
    await pool.request()
      .input("id", sql.Int, id)
      .input("block", sql.Bit, isBlocked ? 1 : 0)
      .query(`UPDATE ${table} SET IsBlocked = @block WHERE ${idField} = @id`);
    res.json({ message: `User successfully ${isBlocked ? 'blocked' : 'unblocked'}.` });
  } catch (err) {
    res.status(500).json({ error: "Server error updating status" });
  }
});

// 👉 NEW: Admin route to send custom emails
app.post("/api/admin/send-email", authMiddleware("admin"), async (req, res) => {
  const { email, subject, message } = req.body;
  try {
    const htmlMessage = `<div style="font-family:Arial,sans-serif;">${message.replace(/\n/g, '<br/>')}</div>`;
    await sendEmail(email, subject, htmlMessage);
    res.json({ message: "Email sent successfully!" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send email" });
  }
});

// ──────────────────────────────────────────────────────────────
// ════════════════  DONOR ROUTES  ════════════════
// ──────────────────────────────────────────────────────────────

app.post("/api/donors/register", [
  body("fullName").notEmpty(), body("email").isEmail(), body("phone").notEmpty(), body("password").isLength({ min: 6 }),
  body("bloodGroup").isIn(["A+","A-","B+","B-","AB+","AB-","O+","O-"]), body("city").notEmpty(),
  body("latitude").isFloat(), body("longitude").isFloat(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { fullName, email, phone, password, bloodGroup, city, latitude, longitude } = req.body;
  try {
    const existing = await pool.request().input("email", sql.NVarChar, email).query("SELECT DonorID FROM Donors WHERE Email = @email");
    if (existing.recordset.length > 0) return res.status(409).json({ error: "A Donor already exists with this email." });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.request()
      .input("fullName", sql.NVarChar, fullName).input("email", sql.NVarChar, email).input("phone", sql.NVarChar, phone)
      .input("hash", sql.NVarChar, hash).input("bg", sql.NVarChar, bloodGroup).input("city", sql.NVarChar, city)
      .input("lat", sql.Float, latitude).input("lng", sql.Float, longitude)
      .query(`INSERT INTO Donors (FullName,Email,Phone,PasswordHash,BloodGroup,City,Latitude,Longitude) OUTPUT INSERTED.DonorID VALUES (@fullName,@email,@phone,@hash,@bg,@city,@lat,@lng)`);

    await sendEmail(email, "Welcome to BloodLink 🩸", `<h2>Hi ${fullName},</h2><p>You are now registered as a <strong>${bloodGroup}</strong> blood donor.</p><p>Your generosity can save lives. Thank you!</p>`);
    res.status(201).json({ message: "Donor registered successfully", donorId: result.recordset[0].DonorID });
  } catch (err) { res.status(500).json({ error: "Server error", detail: err.message }); }
});

app.post("/api/donors/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.request().input("email", sql.NVarChar, email).query("SELECT * FROM Donors WHERE Email = @email");
    const donor = result.recordset[0];
    if (!donor) return res.status(404).json({ error: "Donor not found" });
    
    // 👉 NEW: Blocked Users Check
    if (donor.IsBlocked) return res.status(403).json({ error: "Your account has been blocked by the Administrator." });

    const valid = await bcrypt.compare(password, donor.PasswordHash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: donor.DonorID, email: donor.Email, role: "donor" }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, donor: { ...donor, PasswordHash: undefined } });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/donors/profile", authMiddleware("donor"), async (req, res) => {
  try {
    const result = await pool.request().input("id", sql.Int, req.user.id).query("SELECT DonorID,FullName,Email,Phone,BloodGroup,City,Latitude,Longitude,IsAvailable,LastDonated,CreatedAt FROM Donors WHERE DonorID=@id");
    res.json(result.recordset[0]);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.put("/api/donors/availability", authMiddleware("donor"), async (req, res) => {
  try {
    await pool.request().input("id", sql.Int, req.user.id).input("avail", sql.Bit, req.body.isAvailable ? 1 : 0).query("UPDATE Donors SET IsAvailable=@avail WHERE DonorID=@id");
    res.json({ message: "Availability updated" });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/donors/history", authMiddleware("donor"), async (req, res) => {
  try {
    const result = await pool.request().input("id", sql.Int, req.user.id).query(`SELECT dh.*, r.FullName AS RecipientName, r.Phone AS RecipientPhone FROM DonationHistory dh JOIN Recipients r ON dh.RecipientID = r.RecipientID WHERE dh.DonorID = @id ORDER BY dh.DonatedAt DESC`);
    res.json(result.recordset);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

// ──────────────────────────────────────────────────────────────
// ════════════════  RECIPIENT ROUTES  ════════════════
// ──────────────────────────────────────────────────────────────

app.post("/api/recipients/register", [
  body("fullName").notEmpty(), body("email").isEmail(), body("phone").notEmpty(), body("password").isLength({ min: 6 }),
  body("bloodGroup").isIn(["A+","A-","B+","B-","AB+","AB-","O+","O-"]), body("city").notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { fullName, email, phone, password, bloodGroup, city, latitude = 0, longitude = 0 } = req.body;
  try {
    const existing = await pool.request().input("email", sql.NVarChar, email).query("SELECT RecipientID FROM Recipients WHERE Email = @email");
    if (existing.recordset.length > 0) return res.status(409).json({ error: "A Recipient already exists with this email." });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.request()
      .input("fullName", sql.NVarChar, fullName).input("email", sql.NVarChar, email).input("phone", sql.NVarChar, phone)
      .input("hash", sql.NVarChar, hash).input("bg", sql.NVarChar, bloodGroup).input("city", sql.NVarChar, city)
      .input("lat", sql.Float, latitude).input("lng", sql.Float, longitude)
      .query(`INSERT INTO Recipients (FullName,Email,Phone,PasswordHash,BloodGroup,City,Latitude,Longitude) OUTPUT INSERTED.RecipientID VALUES (@fullName,@email,@phone,@hash,@bg,@city,@lat,@lng)`);
    
    sendEmail(email, "Welcome to BloodLink 🏥", `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:20px;"><div style="background:#1d4ed8;padding:20px;border-radius:12px 12px 0 0;text-align:center;"><h1 style="color:white;margin:0;">🏥 Welcome to BloodLink!</h1></div><div style="border:1px solid #bfdbfe;border-top:none;padding:24px;border-radius:0 0 12px 12px;"><p>Dear <strong>${fullName}</strong>,</p><p>You are now registered as a <strong>Recipient</strong> on BloodLink.</p><p>Stay safe and take care!</p><p style="color:#9ca3af;font-size:12px;">— BloodLink Team</p></div></div>`).catch(()=>{}); 
    res.status(201).json({ message: "Recipient registered", recipientId: result.recordset[0].RecipientID });
  } catch (err) { res.status(500).json({ error: "Server error", detail: err.message }); }
});

app.post("/api/recipients/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.request().input("email", sql.NVarChar, email).query("SELECT * FROM Recipients WHERE Email = @email");
    const rec = result.recordset[0];
    if (!rec) return res.status(404).json({ error: "Recipient not found" });

    // 👉 NEW: Blocked Users Check
    if (rec.IsBlocked) return res.status(403).json({ error: "Your account has been blocked by the Administrator." });

    const valid = await bcrypt.compare(password, rec.PasswordHash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: rec.RecipientID, email: rec.Email, role: "recipient" }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, recipient: { ...rec, PasswordHash: undefined } });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

// ──────────────────────────────────────────────────────────────
// ════════════════  BLOOD REQUEST ROUTES  ════════════════
// ──────────────────────────────────────────────────────────────

app.post("/api/requests", authMiddleware("recipient"), async (req, res) => {
  const { bloodGroup, unitsNeeded = 1, hospitalName, city, latitude, longitude, urgency = "Normal", notes } = req.body;
  try {
    const reqResult = await pool.request()
      .input("recipientId", sql.Int, req.user.id).input("bg", sql.NVarChar, bloodGroup).input("units", sql.Int, unitsNeeded)
      .input("hospital", sql.NVarChar, hospitalName).input("city", sql.NVarChar, city).input("lat", sql.Float, latitude)
      .input("lng", sql.Float, longitude).input("urgency", sql.NVarChar, urgency).input("notes", sql.NVarChar, notes || "")
      .query(`INSERT INTO BloodRequests (RecipientID,BloodGroup,UnitsNeeded,HospitalName,City,Latitude,Longitude,Urgency,Notes) OUTPUT INSERTED.RequestID VALUES (@recipientId,@bg,@units,@hospital,@city,@lat,@lng,@urgency,@notes)`);

    const requestId = reqResult.recordset[0].RequestID;

    const donorsResult = await pool.request()
      .input("bg", sql.NVarChar, bloodGroup).input("lat", sql.Float, latitude).input("lng", sql.Float, longitude)
      .query(`
        SELECT TOP 10 d.DonorID, d.FullName, d.Email, d.Phone, d.BloodGroup, d.City, d.Latitude, d.Longitude,
          ROUND(6371 * 2 * ASIN(SQRT(POWER(SIN(RADIANS(d.Latitude - @lat)/2),2) + COS(RADIANS(@lat))*COS(RADIANS(d.Latitude))*POWER(SIN(RADIANS(d.Longitude - @lng)/2),2))), 2) AS DistanceKM
        FROM Donors d
        WHERE d.IsAvailable = 1 AND d.BloodGroup = @bg AND d.IsBlocked = 0 AND (d.LastDonated IS NULL OR d.LastDonated < DATEADD(DAY, -90, GETDATE()))
        ORDER BY DistanceKM ASC
      `);

    const nearbyDonors = donorsResult.recordset;
    if (nearbyDonors.length === 0) return res.status(200).json({ message: "Request created. No nearby donors found right now.", requestId, donorsNotified: 0 });

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    let notified = 0;

    for (const donor of nearbyDonors) {
      const notifResult = await pool.request().input("requestId", sql.Int, requestId).input("donorId", sql.Int, donor.DonorID).input("expires", sql.DateTime2, expiresAt)
        .query(`INSERT INTO DonorNotifications (RequestID, DonorID, ExpiresAt) OUTPUT INSERTED.NotificationID VALUES (@requestId, @donorId, @expires)`);
      const notificationId = notifResult.recordset[0].NotificationID;
      const acceptURL = `${process.env.FRONTEND_URL || "http://localhost:3000"}/respond?nid=${notificationId}&action=accept`;
      const declineURL = `${process.env.FRONTEND_URL || "http://localhost:3000"}/respond?nid=${notificationId}&action=decline`;

      const emailHtml = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;"><h1 style="color:#c0392b;">🩸 Urgent Blood Needed!</h1><p>Dear <strong>${donor.FullName}</strong>,</p><p>A patient at <strong>${hospitalName}</strong> in <strong>${city}</strong> urgently needs <strong>${bloodGroup}</strong> blood (${unitsNeeded} unit${unitsNeeded > 1 ? "s" : ""}).</p><p>📍 You are approximately <strong>${donor.DistanceKM} km</strong> away.</p><p>⏱️ Urgency: <strong>${urgency}</strong></p>${notes ? `<p>Note: ${notes}</p>` : ""}<p style="margin:30px 0;"><a href="${acceptURL}" style="background:#27ae60;color:white;padding:14px 28px;text-decoration:none;border-radius:6px;font-size:16px;margin-right:12px;">✅ I can donate</a>&nbsp;<a href="${declineURL}" style="background:#c0392b;color:white;padding:14px 28px;text-decoration:none;border-radius:6px;font-size:16px;">❌ Cannot donate</a></p></div>`;
      const ok = await sendEmail(donor.Email, `🩸 Urgent: ${bloodGroup} blood needed near you`, emailHtml);
      if (ok) notified++;
    }
    res.status(201).json({ message: "Request created & donors notified", requestId, donorsNotified: notified, nearbyDonors: nearbyDonors.length });
  } catch (err) { res.status(500).json({ error: "Server error", detail: err.message }); }
});

app.get("/api/requests", async (req, res) => {
  try {
    const result = await pool.request().query(`SELECT br.*, r.FullName AS RecipientName, r.Phone AS RecipientPhone, d.FullName AS DonorName, d.Phone AS DonorPhone FROM BloodRequests br JOIN Recipients r ON br.RecipientID = r.RecipientID LEFT JOIN Donors d ON br.AcceptedByDonorID = d.DonorID ORDER BY br.CreatedAt DESC`);
    res.json(result.recordset);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/requests/me", authMiddleware("recipient"), async (req, res) => {
  try {
    const result = await pool.request().input("recId", sql.Int, req.user.id).query(`SELECT br.*, r.FullName AS RecipientName, r.Phone AS RecipientPhone, d.FullName AS DonorName, d.Phone AS DonorPhone FROM BloodRequests br JOIN Recipients r ON br.RecipientID = r.RecipientID LEFT JOIN Donors d ON br.AcceptedByDonorID = d.DonorID WHERE br.RecipientID = @recId ORDER BY br.CreatedAt DESC`);
    res.json(result.recordset);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/requests/:id", async (req, res) => {
  try {
    const result = await pool.request().input("id", sql.Int, req.params.id).query(`SELECT br.*, r.FullName AS RecipientName, r.Phone AS RecipientPhone, d.FullName AS DonorName, d.Phone AS DonorPhone, d.Email AS DonorEmail FROM BloodRequests br JOIN Recipients r ON br.RecipientID = r.RecipientID LEFT JOIN Donors d ON br.AcceptedByDonorID = d.DonorID WHERE br.RequestID = @id`);
    if (!result.recordset[0]) return res.status(404).json({ error: "Request not found" });
    res.json(result.recordset[0]);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/respond", async (req, res) => {
  const { notificationId, action, estimatedMinutes } = req.body;
  try {
    const notif = await pool.request().input("nid", sql.Int, notificationId).query("SELECT * FROM DonorNotifications WHERE NotificationID=@nid");
    const n = notif.recordset[0];
    if (!n) return res.status(404).json({ error: "Notification not found" });
    if (n.Status !== "Pending") return res.status(409).json({ error: `Already ${n.Status}`, status: n.Status });
    if (new Date() > new Date(n.ExpiresAt)) {
      await pool.request().input("nid", sql.Int, notificationId).query("UPDATE DonorNotifications SET Status='Expired' WHERE NotificationID=@nid");
      return res.status(410).json({ error: "Notification expired" });
    }

    if (action === "decline") {
      await pool.request().input("nid", sql.Int, notificationId).query(`UPDATE DonorNotifications SET Status='Declined', RespondedAt=GETDATE() WHERE NotificationID=@nid`);
      return res.json({ message: "Declined successfully" });
    }

    if (action === "accept") {
      const requestId = n.RequestID; const donorId = n.DonorID; const eta = estimatedMinutes || 30;
      await pool.request().input("nid", sql.Int, notificationId).input("eta", sql.Int, eta).query(`UPDATE DonorNotifications SET Status='Accepted', EstimatedMinutes=@eta, RespondedAt=GETDATE() WHERE NotificationID=@nid`);
      await pool.request().input("requestId", sql.Int, requestId).input("nid", sql.Int, notificationId).query(`UPDATE DonorNotifications SET Status='Cancelled' WHERE RequestID=@requestId AND NotificationID <> @nid AND Status='Pending'`);
      await pool.request().input("requestId", sql.Int, requestId).input("donorId", sql.Int, donorId).query(`UPDATE BloodRequests SET Status='Matched', AcceptedByDonorID=@donorId, UpdatedAt=GETDATE() WHERE RequestID=@requestId`);
      await pool.request().input("donorId", sql.Int, donorId).query("UPDATE Donors SET IsAvailable=0 WHERE DonorID=@donorId");

      const detailResult = await pool.request().input("requestId", sql.Int, requestId).input("donorId", sql.Int, donorId).query(`SELECT br.HospitalName, br.BloodGroup, r.Email AS RecipientEmail, r.FullName AS RecipientName, d.FullName AS DonorName, d.Phone AS DonorPhone FROM BloodRequests br JOIN Recipients r ON br.RecipientID = r.RecipientID JOIN Donors d ON d.DonorID = @donorId WHERE br.RequestID = @requestId`);
      const rd = detailResult.recordset[0];

      if (rd && rd.RecipientEmail) {
        await sendEmail(rd.RecipientEmail, "✅ Donor Found! Help is on the way", `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;"><h1 style="color:#27ae60;">✅ Great News!</h1><p>Dear <strong>${rd.RecipientName}</strong>,</p><p>A donor has accepted your blood request and is on the way!</p><p><strong>Donor Name:</strong> ${rd.DonorName}<br><strong>Donor Phone:</strong> ${rd.DonorPhone}<br><strong>Estimated Arrival:</strong> ~${eta} minutes</p></div>`);
      }
      return res.json({ message: "Accepted! Recipient notified.", estimatedMinutes: eta, donorName: rd?.DonorName || "Donor" });
    }
    res.status(400).json({ error: "Invalid action." });
  } catch (err) { res.status(500).json({ error: "Server error", detail: err.message }); }
});

app.get("/api/notifications/donor/:donorId", authMiddleware("donor"), async (req, res) => {
  try {
    const result = await pool.request().input("did", sql.Int, req.params.donorId).query(`SELECT dn.*, br.BloodGroup, br.HospitalName, br.City, br.Urgency, br.UnitsNeeded, r.FullName AS RecipientName FROM DonorNotifications dn JOIN BloodRequests br ON dn.RequestID = br.RequestID JOIN Recipients r ON br.RecipientID = r.RecipientID WHERE dn.DonorID = @did AND dn.Status = 'Pending' AND dn.ExpiresAt > GETDATE() ORDER BY dn.NotifiedAt DESC`);
    res.json(result.recordset);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/requests/:id/fulfill", authMiddleware("recipient"), async (req, res) => {
  const requestId = parseInt(req.params.id); const unitsGiven = req.body.units || 1;
  try {
    const reqInfo = await pool.request().input("requestId", sql.Int, requestId).query(`SELECT AcceptedByDonorID, RecipientID, HospitalName, BloodGroup FROM BloodRequests WHERE RequestID = @requestId`);
    const info = reqInfo.recordset[0];
    if (!info) return res.status(404).json({ error: "Request not found" });
    if (!info.AcceptedByDonorID) return res.status(400).json({ error: "No donor has accepted this request yet" });

    await pool.request().input("requestId", sql.Int, requestId).input("donorId", sql.Int, info.AcceptedByDonorID).input("recipientId", sql.Int, info.RecipientID).input("hospital", sql.NVarChar, info.HospitalName).input("bg", sql.NVarChar, info.BloodGroup).input("units", sql.Int, unitsGiven).query(`INSERT INTO DonationHistory (RequestID, DonorID, RecipientID, HospitalName, BloodGroup, UnitsGiven) VALUES (@requestId, @donorId, @recipientId, @hospital, @bg, @units)`);
    await pool.request().input("requestId", sql.Int, requestId).query(`UPDATE BloodRequests SET Status='Fulfilled', UpdatedAt=GETDATE() WHERE RequestID=@requestId`);
    await pool.request().input("donorId", sql.Int, info.AcceptedByDonorID).query(`UPDATE Donors SET IsAvailable=1, LastDonated=CAST(GETDATE() AS DATE) WHERE DonorID=@donorId`);
    res.json({ message: "Donation marked as fulfilled! Thank you!" });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/stats", async (req, res) => {
  try {
    const result = await pool.request().query(`SELECT (SELECT COUNT(*) FROM Donors) AS totalDonors, (SELECT COUNT(*) FROM Donors WHERE IsAvailable=1 AND IsBlocked=0) AS availableDonors, (SELECT COUNT(*) FROM Recipients) AS totalRecipients, (SELECT COUNT(*) FROM BloodRequests) AS totalRequests, (SELECT COUNT(*) FROM BloodRequests WHERE Status='Fulfilled') AS fulfilledRequests, (SELECT COUNT(*) FROM BloodRequests WHERE Status='Pending') AS pendingRequests, (SELECT COUNT(*) FROM DonationHistory) AS totalDonations`);
    res.json(result.recordset[0]);
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🩸 BloodLink API running on port ${PORT}`));
module.exports = app;
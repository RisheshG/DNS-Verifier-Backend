const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const dns = require("dns");
const fastCsv = require("fast-csv");
const admin = require("firebase-admin");
const { getAuth } = require("firebase-admin/auth");

// Initialize Firebase Admin
const serviceAccount = require("./dns-verifier-firebase-adminsdk-fbsvc-e7ccaed22e.json");
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

const app = express();
const PORT = 5001;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: "uploads/" });

// Helper function to extract domain from email
const getDomain = (email) => {
    const parts = email.split("@");
    return parts.length === 2 ? parts[1] : null;
};

// Function to check DNS records
const checkDNS = async (domain) => {
    const results = { MX: false, SPF: false, DKIM: false, DMARC: false };
    const commonEmailProviders = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"];

    if (commonEmailProviders.includes(domain)) {
        return { MX: true, SPF: true, DKIM: true, DMARC: true };
    }

    try {
        results.MX = (await dns.promises.resolveMx(domain)).length > 0;
    } catch {}

    try {
        const txtRecords = await dns.promises.resolveTxt(domain);
        txtRecords.forEach((record) => {
            if (record.join("").includes("v=spf1")) results.SPF = true;
        });
    } catch {}

    try {
        let dkimSelectors = ["dkim", "google", "selector1", "selector2"];
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=TXT`);
        const data = await response.json();

        if (data.Answer) {
            data.Answer.forEach((record) => {
                if (record.data.includes("v=DKIM1")) {
                    const match = record.name.match(/([^\.]+)\._domainkey\./);
                    if (match) {
                        dkimSelectors.push(match[1]);
                    }
                }
            });
        }

        const dkimRecords = await Promise.all(
            dkimSelectors.map(selector =>
                dns.promises.resolveTxt(`${selector}._domainkey.${domain}`).catch(() => [])
            )
        );

        results.DKIM = dkimRecords.some(record =>
            record.some(txt => txt.join("").includes("v=DKIM1"))
        );
    } catch (error) {
        console.error("Error fetching DKIM selectors:", error);
    }

    try {
        const dmarcRecords = await dns.promises.resolveTxt(`_dmarc.${domain}`).catch(() => []);
        results.DMARC = dmarcRecords.some((record) => record.join("").includes("v=DMARC1"));
    } catch {}

    return results;
};

// User Registration Route
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const userRecord = await getAuth().createUser({
            email,
            password,
        });

        res.status(201).json({ message: "User registered successfully", user: userRecord });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: error.message });
    }
});

// User Login Route
app.post("/login", async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }

    try {
        const user = await getAuth().getUserByEmail(email);

        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }

        const customToken = await getAuth().createCustomToken(user.uid);
        res.json({ token: customToken });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Middleware to verify Firebase token
const verifyFirebaseToken = async (req, res, next) => {
    const token = req.headers.authorization?.split("Bearer ")[1];

    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    try {
        const decodedToken = await getAuth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
};

// Protected Route Example
app.get("/protected", verifyFirebaseToken, (req, res) => {
    res.json({ message: "This is a protected route", user: req.user });
});

// File Upload and DNS Verification
app.post("/upload", upload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const selectedColumn = req.body.column;
    const filePath = req.file.path;
    const rows = [];
    const results = [];
    const categories = {};

    fs.createReadStream(filePath)
        .pipe(fastCsv.parse({ headers: true }))
        .on("data", (row) => rows.push(row))
        .on("end", async () => {
            for (const row of rows) {
                const email = row[selectedColumn];
                if (!email) continue;

                const domain = getDomain(email);
                if (!domain) continue;

                const dnsResults = await checkDNS(domain);

                const missingRecords = [];
                if (!dnsResults.MX) missingRecords.push("No MX");
                if (!dnsResults.SPF) missingRecords.push("No SPF");
                if (!dnsResults.DKIM) missingRecords.push("No DKIM");
                if (!dnsResults.DMARC) missingRecords.push("No DMARC");

                const category = missingRecords.length
                    ? `Missing: ${missingRecords.join(", ")}`
                    : "All Records Found";

                if (!categories[category]) categories[category] = [];
                categories[category].push({ ...row, domain, ...dnsResults });
            }

            const downloadLinks = [];

            for (const category in categories) {
                const outputFile = `downloads/${category.replace(/[^a-zA-Z0-9]/g, "_")}.csv`;
                const ws = fs.createWriteStream(outputFile);
                fastCsv.write(categories[category], { headers: true }).pipe(ws);
                downloadLinks.push({ category, file: outputFile });
            }

            res.json({ downloadLinks });
        });
});

app.get("/download/:filename", (req, res) => {
    const filePath = path.join(__dirname, "downloads", req.params.filename);
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: "File not found" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

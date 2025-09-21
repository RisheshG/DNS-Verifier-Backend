const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const dns = require("dns");
const fastCsv = require("fast-csv");

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

    // Skip DNS checks for common email providers
    if (commonEmailProviders.includes(domain)) {
        return { MX: true, SPF: true, DKIM: true, DMARC: true };
    }

    // Check MX records
    try {
        const mxRecords = await dns.promises.resolveMx(domain);
        results.MX = mxRecords.length > 0;
    } catch (error) {
        console.error(`MX lookup failed for ${domain}:`, error.message);
    }

    // Check SPF records
    try {
        const txtRecords = await dns.promises.resolveTxt(domain);
        results.SPF = txtRecords.some((record) => record.join("").includes("v=spf1"));
    } catch (error) {
        console.error(`SPF lookup failed for ${domain}:`, error.message);
    }

    // Check DKIM records
    try {
        const dkimSelectors = ["dkim", "google", "selector1", "selector2"];
        const dkimRecords = await Promise.all(
            dkimSelectors.map((selector) =>
                dns.promises.resolveTxt(`${selector}._domainkey.${domain}`).catch(() => [])
            )
        );
        results.DKIM = dkimRecords.some((record) =>
            record.some((txt) => txt.join("").includes("v=DKIM1"))
        );
    } catch (error) {
        console.error(`DKIM lookup failed for ${domain}:`, error.message);
    }

    // Check DMARC records
    try {
        const dmarcRecords = await dns.promises.resolveTxt(`_dmarc.${domain}`).catch(() => []);
        results.DMARC = dmarcRecords.some((record) => record.join("").includes("v=DMARC1"));
    } catch (error) {
        console.error(`DMARC lookup failed for ${domain}:`, error.message);
    }

    return results;
};

// File Upload and DNS Verification
app.post("/upload", upload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const selectedColumn = req.body.column;
    const filePath = req.file.path;
    const rows = [];
    const results = [];
    const categories = {};

    const batchSize = 1000; // Process 1000 rows at a time
    let batch = [];

    fs.createReadStream(filePath)
        .pipe(fastCsv.parse({ headers: true }))
        .on("data", (row) => {
            batch.push(row);
            if (batch.length >= batchSize) {
                rows.push(...batch);
                batch = [];
            }
        })
        .on("end", async () => {
            if (batch.length > 0) {
                rows.push(...batch);
            }

            for (let i = 0; i < rows.length; i += batchSize) {
                const batchRows = rows.slice(i, i + batchSize);
                const batchResults = await Promise.all(batchRows.map(async (row) => {
                    const email = row[selectedColumn];
                    if (!email) return null;

                    const domain = getDomain(email);
                    if (!domain) return null;

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

                    // Retain original columns and append DNS results
                    const resultRow = { ...row, domain, ...dnsResults };
                    categories[category].push(resultRow);
                    return resultRow;
                }));

                results.push(...batchResults.filter((row) => row !== null));
            }

            const downloadLinks = [];

            for (const category in categories) {
                const outputFile = `downloads/${category.replace(/[^a-zA-Z0-9]/g, "_")}.csv`;
                const ws = fs.createWriteStream(outputFile);

                // Write the original headers along with the new DNS result headers
                const headers = Object.keys(rows[0]).concat(["domain", "MX", "SPF", "DKIM", "DMARC"]);
                fastCsv.write(categories[category], { headers }).pipe(ws);

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

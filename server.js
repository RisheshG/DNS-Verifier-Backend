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

    // Check DKIM records (expanded selectors)
    try {
        const checkDKIM = async (domain, selector = null) => {
            const selectors = selector 
                ? [selector] 
                : [
                    "default", "mail", "email", "smtp", "mx", "selector", "dkim", "sig1", "key1", "key2",
                    "s1", "s2", "k1", "k2", "m1", "m2",
                    "google", "google1", "google2", "google3", "google4",
                    "selector1", "selector2", "selector3", "selector4",
                    "zoho", "zoho1", "zoho2", "zoho3",
                    "mandrill", "mailchimp",
                    "amazonses", "ses",
                    "pm1", "pm2", "fm1", "fm2", "yahoo", "yahoo1", "yahoo2",
                    "protonmail", "mx1", "mx2", "smtp1", "smtp2", "sig", "dkim1", "dkim2", "dkim3",
                    "email1", "email2"
                ];

            for (const sel of selectors) {
                try {
                    const records = await dns.promises.resolveTxt(`${sel}._domainkey.${domain}`);
                    if (records.some(r => r.join("").includes("v=DKIM1"))) {
                        return true;
                    }
                } catch (error) {
                    continue; // ignore if selector not found
                }
            }
            return false;
        };

        results.DKIM = await checkDKIM(domain);
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

    const allRecordsFound = [];
    const missingRecords = [];

    const batchSize = 1000;
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

                    // Check if any DNS record is missing
                    const anyMissing = !dnsResults.MX || !dnsResults.SPF || !dnsResults.DKIM || !dnsResults.DMARC;

                    // Retain original columns and append DNS results
                    const resultRow = { ...row, domain, ...dnsResults };

                    if (anyMissing) {
                        missingRecords.push(resultRow);
                    } else {
                        allRecordsFound.push(resultRow);
                    }

                    return resultRow;
                }));

                // Filter out null rows
                batchResults.filter((row) => row !== null);
            }

            // Ensure downloads folder exists
            if (!fs.existsSync("downloads")) fs.mkdirSync("downloads");

            // Prepare download links
            const downloadLinks = [];

            const files = [
                { name: "All_Records_Found", data: allRecordsFound },
                { name: "Missing_Records", data: missingRecords }
            ];

            for (const file of files) {
                const outputFile = path.join("downloads", `${file.name}.csv`);
                const ws = fs.createWriteStream(outputFile);

                // Use original headers + DNS results
                const headers = Object.keys(rows[0]).concat(["domain", "MX", "SPF", "DKIM", "DMARC"]);
                fastCsv.write(file.data, { headers }).pipe(ws);

                downloadLinks.push({ 
                    category: file.name, 
                    count: file.data.length, 
                    file: outputFile 
                });
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

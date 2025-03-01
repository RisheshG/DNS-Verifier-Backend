const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const dns = require("dns");
const fastCsv = require("fast-csv");

const downloadsDir = path.join(__dirname, "downloads");
if (!fs.existsSync(downloadsDir)) {
    fs.mkdirSync(downloadsDir);
}

const app = express();
const PORT = 5001;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: "uploads/" });

const getDomain = (email) => {
    const parts = email.split("@");
    return parts.length === 2 ? parts[1] : null;
};

const checkDNS = async (domain) => {
    const results = {
        MX: false,
        SPF: false,
        DKIM: false,
        DMARC: false,
    };

    // List of common email providers
    const commonEmailProviders = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"];

    // If the domain is a common email provider, skip DNS checks and return all records as found
    if (commonEmailProviders.includes(domain)) {
        return {
            MX: true,
            SPF: true,
            DKIM: true,
            DMARC: true,
        };
    }

    // Perform DNS checks for non-common domains
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
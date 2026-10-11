
const SUPABASE_URL =
"https://kgscurlvuevcpkaxdxur.supabase.co";

const SUPABASE_ANON_KEY =
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtnc2N1cmx2dWV2Y3BrYXhkeHVyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODExMDM3MzYsImV4cCI6MjA5NjY3OTczNn0.l01Gx-gvoNzYHejrJPa7-TSYdmGApP89LByDr4pIQ9o";

const supabaseClient =
window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_ANON_KEY
);

const reportButton =
document.getElementById(
    "openReportForm"
);

if (reportButton) {

    reportButton.addEventListener(
        "click",
        showReportForm
    );

}

function showReportForm() {

    document.getElementById(
        "content"
    ).innerHTML = `
        <h3>Report Problem</h3>

        <p>Full Name</p>

        <input
            type="text"
            id="reportName"
        >

        <p>Describe the issue</p>

        <textarea
            id="reportText"
            rows="10"
            style="
                width:100%;
                box-sizing:border-box;
            "
        ></textarea>

        <br><br>

        <button
            id="submitReport"
        >
            Submit Report
        </button>
    `;

    document
        .getElementById(
            "submitReport"
        )
        .addEventListener(
            "click",
            submitReport
        );

}

async function submitReport() {

    const fullName =
    document
        .getElementById(
            "reportName"
        )
        .value
        .trim();

    const reportText =
    document
        .getElementById(
            "reportText"
        )
        .value
        .trim();

    if (!fullName) {

        alert(
            "Full Name is required."
        );

        return;

    }

    if (!reportText) {

        alert(
            "Problem Description is required."
        );

        return;

    }

    let headers = {
        "Content-Type":
            "application/json"
    };

    const {
        data: { session }
    } =
    await supabaseClient
        .auth
        .getSession();

    if (session) {

        headers.Authorization =
            `Bearer ${session.access_token}`;

    }

    const response =
    await fetch(
        "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/submit-report",
        {
            method: "POST",
            headers,
            body: JSON.stringify({
                fullName,
                reportText
            })
        }
    );

    const result =
    await response.json();

    if (!response.ok) {
await fetch(
    "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/log-action",
    {
        method: "POST",
        headers,
        body: JSON.stringify({
            action:
                "REPORT_SUBMITTED"
        })
    }
);
        alert(
            result.error ||
            "Failed to submit report."
        );

        return;

    }

    document.getElementById(
        "content"
    ).innerHTML = `
        <h3>Thank You</h3>

        <p>
            Thank you for reporting
            this problem.
        </p>
    `;

}
# HelpBridge — upgraded full-stack academic prototype

**Project title:** HelpBridge: A Dual-Channel Blood Availability and Emergency Coordination System

## What's included in this upgrade
- Existing login, donor search, blood requests, request tracking and blood-bank directory.
- Mandatory donor health disclosure questionnaire during donor registration.
- Private donor health declarations stored separately from public donor listings.
- Donors appear in search only after submitting the declaration and consenting to contact.
- Consent-based contact requests: requester asks, donor accepts/declines, and donor phone is shown to the requester only after acceptance.
- Audit events for health declaration and contact-request actions.
- Verified-bank-only inventory reads; real stock must be entered by authorized bank staff.
- Responsive existing HelpBridge visual design retained.

## Important safety and privacy limits
This is a student prototype, not a medical screening or emergency service. Health questionnaire answers are self-disclosures only; they do not determine eligibility. A licensed blood bank must independently screen each donor and decide eligibility. Blood group alone does not establish transfusion compatibility.

Health disclosure answers are sensitive information. This academic build stores them in a restricted database table and does not return them in donor search, but it does not yet implement field-level encryption, a full clinical privacy review, or production-grade role provisioning. Use fictional data only for college demonstrations. Do not enter real patient or donor health information into a public deployment.

The demo records are fictional. Demo blood banks are deliberately unverified and have no inventory. Never present demo data as live availability.

## Setup / upgrade
1. Make a backup of your current project folder and MySQL database.
2. Extract this ZIP and open the `HelpBridge_FullStack` folder in VS Code.
3. In MySQL Workbench, run the updated `database.sql` against your existing `helpbridge` schema. It uses `CREATE TABLE IF NOT EXISTS` and preserves existing tables and rows while adding the new workflow tables.
4. Optional: run `demo_data.sql` to add clearly fictional donor records for demonstration. This script can be re-run; the sample donors remain fictional and cannot log in.
5. Keep your existing `.env` values or copy `.env.example` to `.env`; set DB credentials and a strong `JWT_SECRET` (at least 32 characters).
6. In the project terminal run `npm install`, then `npm start`.
7. Open `http://localhost:3000`.

If `npm start` says the port is in use, stop the previous Node process with Ctrl+C before restarting.

## Demo workflow
1. Register a requester account.
2. Register a donor account and complete every health disclosure question and declaration.
3. Sign in as requester and search for the donor.
4. Select **Request contact**.
5. Sign in as the donor and open **Contact requests**; accept or decline.
6. Sign in as requester and revisit **Contact requests**. The donor phone is shown only if accepted.
7. Create a blood request and track its status under **My requests**.

## Database tables
`users`, `donor_profiles`, `donor_health_disclosures`, `donor_contact_requests`, `audit_events`, `blood_banks`, `inventory`, `blood_requests`, `request_updates`.

## API additions
- `GET /api/donors/me/health`
- `PUT /api/donors/me/health`
- `POST /api/donors/:id/contact-requests`
- `GET /api/contact-requests`
- `PATCH /api/contact-requests/:id`

## Still future work
- Admin UI for blood-bank verification and user-role provisioning.
- Bank-to-staff ownership mapping and stricter inventory authorization.
- Encrypted health-data storage, consent withdrawal workflow and retention controls.
- SMS/email/WhatsApp notifications (not configured in this project).
- Request timeline UI and full professional screening integration.
- Security, privacy and usability review before any real-world pilot.

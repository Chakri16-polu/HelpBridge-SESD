require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || true }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 180 }));
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12 });
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "helpbridge",
  waitForConnections: true, connectionLimit: 10, queueLimit: 0
});
const GROUPS = ["A+","A-","B+","B-","AB+","AB-","O+","O-"];
const COMPONENTS = ["Packed red cells","Whole blood","Platelets","Plasma"];
const clean = (v, max=180) => typeof v === "string" ? v.trim().slice(0,max) : "";
const validPhone = v => /^[0-9]{10,15}$/.test(v || "");
function tokenFor(user) {
  return jwt.sign({ id:user.id, role:user.role }, process.env.JWT_SECRET, { expiresIn:"8h" });
}
async function requireAuth(req,res,next) {
  try {
    const raw=(req.headers.authorization || "").replace(/^Bearer\s+/i,"");
    if(!raw) return res.status(401).json({error:"Please sign in first."});
    req.user=jwt.verify(raw,process.env.JWT_SECRET);
    next();
  } catch { return res.status(401).json({error:"Session expired. Please sign in again."}); }
}
const allow = (...roles) => (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:"You do not have permission for this action."});

app.post("/api/auth/register", authLimit, async (req,res,next) => {
  try {
    const name=clean(req.body.name,100), email=clean(req.body.email,190).toLowerCase();
    const phone=clean(req.body.phone,15), city=clean(req.body.city,100);
    const password=String(req.body.password || ""), role="requester";
    if(!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validPhone(phone) || !city || password.length<8)
      return res.status(400).json({error:"Enter valid details. Password must contain at least 8 characters."});
    const hash=await bcrypt.hash(password,12);
    const [r]=await pool.execute("INSERT INTO users(name,email,phone,password_hash,role,city) VALUES(?,?,?,?,?,?)",[name,email,phone,hash,role,city]);
    const user={id:r.insertId,name,email,role,city};
    res.status(201).json({token:tokenFor(user),user});
  } catch(e) { if(e.code==="ER_DUP_ENTRY") return res.status(409).json({error:"Email is already registered."}); next(e); }
});
app.post("/api/auth/login", authLimit, async (req,res,next) => {
  try {
    const email=clean(req.body.email,190).toLowerCase(), password=String(req.body.password||"");
    const [rows]=await pool.execute("SELECT id,name,email,phone,password_hash,role,city FROM users WHERE email=?",[email]);
    if(!rows.length || !(await bcrypt.compare(password,rows[0].password_hash))) return res.status(401).json({error:"Incorrect email or password."});
    const u=rows[0]; delete u.password_hash;
    res.json({token:tokenFor(u),user:{id:u.id,name:u.name,email:u.email,role:u.role,city:u.city}});
  } catch(e){next(e);}
});
app.get("/api/me",requireAuth,async(req,res,next)=>{try{const [r]=await pool.execute("SELECT id,name,email,phone,role,city FROM users WHERE id=?",[req.user.id]);if(!r.length)return res.status(404).json({error:"User not found"});res.json(r[0]);}catch(e){next(e);}});
// Donor application is separate from normal account registration.
app.post("/api/donors/me/application",requireAuth,allow("requester","donor"),async(req,res,next)=>{
  const conn=await pool.getConnection();
  try{
    const group=req.body.blood_group, lastDonation=req.body.last_donation_date||null;
    if(!GROUPS.includes(group))return res.status(400).json({error:"Select a valid blood group."});
    if(lastDonation && !/^\d{4}-\d{2}-\d{2}$/.test(lastDonation))return res.status(400).json({error:"Enter a valid last donation date."});
    const answers=req.body.answers;
    if(!answers || HEALTH_KEYS.some(k=>!['yes','no','not_sure'].includes(answers[k])))return res.status(400).json({error:"Please answer every health disclosure question."});
    if(req.body.declaration!==true || req.body.consent_to_contact!==true)return res.status(400).json({error:"Please accept the declaration and donor contact consent."});
    await conn.beginTransaction();
    await conn.execute("INSERT INTO donor_profiles(user_id,blood_group,available,last_donation_date,consent_to_contact) VALUES(?,?,0,?,1) ON DUPLICATE KEY UPDATE blood_group=VALUES(blood_group),available=0,last_donation_date=VALUES(last_donation_date),consent_to_contact=1",[req.user.id,group,lastDonation]);
    const declaration="I confirm these answers are truthful to the best of my knowledge. I understand that this form does not determine eligibility and a licensed blood bank must conduct professional screening.";
    await conn.execute(`INSERT INTO donor_health_disclosures(donor_user_id,answers_json,declaration_text,screening_status) VALUES(?,?,?,'Pending professional screening') ON DUPLICATE KEY UPDATE answers_json=VALUES(answers_json),declaration_text=VALUES(declaration_text),declared_at=CURRENT_TIMESTAMP,screening_status='Pending professional screening',screening_note=NULL,reviewed_by=NULL,reviewed_at=NULL`,[req.user.id,JSON.stringify(answers),declaration]);
    await conn.execute("INSERT INTO audit_events(actor_user_id,event_type,target_user_id,details) VALUES(?,?,?,?)",[req.user.id,"DONOR_APPLICATION_SUBMITTED",req.user.id,"Donor application submitted; availability disabled pending approval"]);
    await conn.commit();
    res.status(201).json({message:"Application submitted. It will remain hidden until professional approval."});
  }catch(e){await conn.rollback();next(e);}finally{conn.release();}
});
app.get("/api/donors/me/application",requireAuth,allow("requester","donor"),async(req,res,next)=>{
  try{
    const [rows]=await pool.execute(`SELECT d.blood_group,d.available,d.last_donation_date,d.consent_to_contact,h.screening_status,h.screening_note,h.declared_at FROM donor_profiles d LEFT JOIN donor_health_disclosures h ON h.donor_user_id=d.user_id WHERE d.user_id=?`,[req.user.id]);
    res.json(rows[0]||{submitted:false});
  }catch(e){next(e);}
});
// Only administrator accounts can review in this MVP; health answers are never exposed publicly.
app.get("/api/admin/donor-applications",requireAuth,allow("admin"),async(req,res,next)=>{
  try{
    const [rows]=await pool.execute(`SELECT u.id AS donor_user_id,u.name,u.city,u.phone,d.blood_group,d.last_donation_date,h.answers_json,h.declaration_text,h.declared_at,h.screening_status FROM donor_profiles d JOIN users u ON u.id=d.user_id JOIN donor_health_disclosures h ON h.donor_user_id=u.id WHERE h.screening_status='Pending professional screening' ORDER BY h.declared_at ASC`);
    res.json(rows);
  }catch(e){next(e);}
});
app.patch("/api/admin/donor-applications/:userId",requireAuth,allow("admin"),async(req,res,next)=>{
  try{
    const userId=Number(req.params.userId), decision=req.body.decision, note=clean(req.body.note,500);
    if(!Number.isInteger(userId)||userId<1||!['Approved','Not approved'].includes(decision))return res.status(400).json({error:"Choose Approved or Not approved."});
    const [r]=await pool.execute("UPDATE donor_health_disclosures SET screening_status=?,screening_note=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE donor_user_id=? AND screening_status='Pending professional screening'",[decision,note||null,req.user.id,userId]);
    if(!r.affectedRows)return res.status(404).json({error:"Pending application not found."});
    if(decision==='Approved') await pool.execute("UPDATE donor_profiles SET available=1 WHERE user_id=? AND consent_to_contact=1",[userId]);
    else await pool.execute("UPDATE donor_profiles SET available=0 WHERE user_id=?",[userId]);
    await pool.execute("INSERT INTO audit_events(actor_user_id,event_type,target_user_id,details) VALUES(?,?,?,?)",[req.user.id,"DONOR_APPLICATION_REVIEWED",userId,`Decision: ${decision}`]);
    res.json({message:`Donor application marked ${decision.toLowerCase()}.`});
  }catch(e){next(e);}
});

app.get("/api/donors",requireAuth,async(req,res,next)=>{
  try {
    const group=clean(req.query.blood_group,3), city=clean(req.query.city,100);
    if(group && !GROUPS.includes(group))return res.status(400).json({error:"Invalid blood group."});
    let sql="SELECT u.id,u.name,u.city,d.blood_group FROM donor_profiles d JOIN users u ON u.id=d.user_id JOIN donor_health_disclosures h ON h.donor_user_id=u.id WHERE d.available=1 AND d.consent_to_contact=1 AND h.screening_status='Approved'";
    const args=[]; if(group){sql+=" AND d.blood_group=?";args.push(group);} if(city){sql+=" AND LOWER(u.city)=LOWER(?)";args.push(city);}
    sql+=" ORDER BY u.city,u.name LIMIT 100";
    const [rows]=await pool.execute(sql,args);res.json(rows);
  }catch(e){next(e);}
});
app.put("/api/donors/me",requireAuth,allow("requester","donor"),async(req,res,next)=>{
  try{
    const group=req.body.blood_group, available=!!req.body.available, consent=!!req.body.consent_to_contact;
    const lastDonation=req.body.last_donation_date||null;
    if(!GROUPS.includes(group))return res.status(400).json({error:"Invalid blood group."});
    if(lastDonation && !/^\d{4}-\d{2}-\d{2}$/.test(lastDonation))return res.status(400).json({error:"Enter a valid last donation date."});
    await pool.execute("UPDATE donor_profiles SET blood_group=?,available=?,consent_to_contact=?,last_donation_date=? WHERE user_id=?",[group,available,consent,lastDonation,req.user.id]);
    res.json({message:"Donor profile updated."});
  }catch(e){next(e);}
});
app.post("/api/requests",requireAuth,async(req,res,next)=>{
  try{
    const {blood_group,component}=req.body, units=Number(req.body.units);
    const hospital=clean(req.body.hospital),city=clean(req.body.city,100),phone=clean(req.body.contact_phone,15);
    const urgency=["Urgent","Within 24 hours","Scheduled"].includes(req.body.urgency)?req.body.urgency:"Urgent";
    const notes=clean(req.body.notes,500);
    if(!GROUPS.includes(blood_group)||!COMPONENTS.includes(component)||!Number.isInteger(units)||units<1||units>20||!hospital||!city||!validPhone(phone))
      return res.status(400).json({error:"Please complete all required fields with valid values."});
    const [r]=await pool.execute("INSERT INTO blood_requests(requester_id,blood_group,component,units,hospital,city,urgency,contact_phone,notes) VALUES(?,?,?,?,?,?,?,?,?)",[req.user.id,blood_group,component,units,hospital,city,urgency,phone,notes||null]);
    res.status(201).json({id:r.insertId,message:"Request created. Contact your hospital and licensed blood bank directly while coordination proceeds."});
  }catch(e){next(e);}
});
app.get("/api/requests",requireAuth,async(req,res,next)=>{
  try{
    let sql="SELECT r.id,r.blood_group,r.component,r.units,r.hospital,r.city,r.urgency,r.status,r.created_at,u.name AS requester_name FROM blood_requests r JOIN users u ON u.id=r.requester_id";
    const args=[];
    if(req.user.role!=="admin"){sql+=" WHERE r.requester_id=?";args.push(req.user.id);}
    sql+=" ORDER BY r.created_at DESC LIMIT 100";
    const [rows]=await pool.execute(sql,args);res.json(rows);
  }catch(e){next(e);}
});
app.patch("/api/requests/:id/status",requireAuth,async(req,res,next)=>{
  try{
    const id=Number(req.params.id), status=req.body.status, note=clean(req.body.note,500);
    if(!Number.isInteger(id)||id<1||!["Coordinating","Fulfilled","Cancelled"].includes(status))return res.status(400).json({error:"Invalid request or status."});
    const [rows]=await pool.execute("SELECT requester_id FROM blood_requests WHERE id=?",[id]);
    if(!rows.length)return res.status(404).json({error:"Request not found."});
    if(req.user.role!=="admin" && Number(rows[0].requester_id)!==Number(req.user.id))return res.status(403).json({error:"You cannot update this request."});
    await pool.execute("UPDATE blood_requests SET status=? WHERE id=?",[status,id]);
    await pool.execute("INSERT INTO request_updates(request_id,actor_id,status,note) VALUES(?,?,?,?)",[id,req.user.id,status,note||null]);
    res.json({message:"Request status updated."});
  }catch(e){next(e);}
});
app.get("/api/banks",requireAuth,async(req,res,next)=>{
  try{
    const city=clean(req.query.city,100);
    let sql="SELECT id,name,city,address,phone,verified FROM blood_banks";const args=[];
    if(city){sql+=" WHERE LOWER(city)=LOWER(?)";args.push(city);}
    sql+=" ORDER BY verified DESC,name LIMIT 100";
    const [rows]=await pool.execute(sql,args);res.json(rows);
  }catch(e){next(e);}
});
app.get("/api/banks/:id/inventory",requireAuth,async(req,res,next)=>{
  try{const [rows]=await pool.execute("SELECT i.blood_group,i.component,i.units,i.updated_at FROM inventory i JOIN blood_banks b ON b.id=i.bank_id WHERE i.bank_id=? AND b.verified=1 ORDER BY i.blood_group,i.component",[Number(req.params.id)]);res.json(rows);}catch(e){next(e);}
});
app.post("/api/banks",requireAuth,allow("admin"),async(req,res,next)=>{
  try{
    const name=clean(req.body.name),city=clean(req.body.city,100),address=clean(req.body.address),phone=clean(req.body.phone,15);
    if(!name||!city||!address||!validPhone(phone))return res.status(400).json({error:"Enter valid bank details."});
    const [r]=await pool.execute("INSERT INTO blood_banks(name,city,address,phone,verified) VALUES(?,?,?,?,0)",[name,city,address,phone]);
    res.status(201).json({id:r.insertId,message:"Bank added as unverified. Admin verification is required."});
  }catch(e){next(e);}
});
app.put("/api/banks/:id/inventory",requireAuth,allow("admin","bank_staff"),async(req,res,next)=>{
  try{
    const bankId=Number(req.params.id),group=req.body.blood_group,component=req.body.component,units=Number(req.body.units);
    if(!Number.isInteger(bankId)||bankId<1||!GROUPS.includes(group)||!COMPONENTS.includes(component)||!Number.isInteger(units)||units<0||units>10000)return res.status(400).json({error:"Invalid inventory values."});
    const [b]=await pool.execute("SELECT id FROM blood_banks WHERE id=? AND verified=1",[bankId]);
    if(!b.length)return res.status(404).json({error:"Verified bank not found."});
    await pool.execute("INSERT INTO inventory(bank_id,blood_group,component,units) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE units=VALUES(units)",[bankId,group,component,units]);
    res.json({message:"Inventory updated. Ensure the bank maintains accurate, current stock records."});
  }catch(e){next(e);}
});
// Donor health declarations are private and visible only to the donor and authorized reviewers.
const HEALTH_KEYS = ["feeling_well","recent_illness","medical_condition","current_medication","recent_donation","doctor_advised_against","recent_procedure","consent_to_screening"];
app.get("/api/donors/me/health",requireAuth,allow("requester","donor"),async(req,res,next)=>{
  try{
    const [rows]=await pool.execute("SELECT answers_json,declaration_text,declared_at,updated_at,screening_status,screening_note FROM donor_health_disclosures WHERE donor_user_id=?",[req.user.id]);
    if(!rows.length)return res.json({submitted:false});
    res.json({submitted:true,...rows[0],answers:rows[0].answers_json});
  }catch(e){next(e);}
});
app.put("/api/donors/me/health",requireAuth,allow("requester","donor"),async(req,res,next)=>{
  try{
    const answers=req.body.answers;
    if(!answers || HEALTH_KEYS.some(k=>!['yes','no','not_sure'].includes(answers[k])))
      return res.status(400).json({error:"Please answer every health disclosure question."});
    if(req.body.declaration!==true)return res.status(400).json({error:"Please confirm the declaration before submitting."});
    const declaration="I confirm that these answers are truthful and complete to the best of my knowledge. I understand that this form does not determine donation eligibility and that a licensed blood bank must conduct its own screening.";
    await pool.execute(`INSERT INTO donor_health_disclosures(donor_user_id,answers_json,declaration_text,screening_status)
      VALUES(?,?,?,'Pending professional screening') ON DUPLICATE KEY UPDATE answers_json=VALUES(answers_json),declaration_text=VALUES(declaration_text),declared_at=CURRENT_TIMESTAMP,screening_status='Pending professional screening',screening_note=NULL,reviewed_by=NULL,reviewed_at=NULL`,
      [req.user.id,JSON.stringify(answers),declaration]);
    await pool.execute("INSERT INTO audit_events(actor_user_id,event_type,target_user_id,details) VALUES(?,?,?,?)",[req.user.id,"DONOR_HEALTH_DECLARATION_SUBMITTED",req.user.id,"Donor submitted or updated private health declaration"]);
    res.json({message:"Health declaration saved privately. Professional screening is still required."});
  }catch(e){next(e);}
});
app.post("/api/donors/:id/contact-requests",requireAuth,async(req,res,next)=>{
  try{
    const donorId=Number(req.params.id),message=clean(req.body.message,300);
    if(!Number.isInteger(donorId)||donorId<1||donorId===Number(req.user.id))return res.status(400).json({error:"Invalid donor."});
    const [donors]=await pool.execute(`SELECT d.user_id FROM donor_profiles d JOIN donor_health_disclosures h ON h.donor_user_id=d.user_id WHERE d.user_id=? AND d.available=1 AND d.consent_to_contact=1 AND h.screening_status='Approved'`,[donorId]);
    if(!donors.length)return res.status(404).json({error:"This donor is not currently listed for contact."});
    const [existing]=await pool.execute("SELECT id FROM donor_contact_requests WHERE donor_user_id=? AND requester_user_id=? AND status='Pending'",[donorId,req.user.id]);
    if(existing.length)return res.status(409).json({error:"You already have a pending contact request for this donor."});
    const [r]=await pool.execute("INSERT INTO donor_contact_requests(donor_user_id,requester_user_id,message) VALUES(?,?,?)",[donorId,req.user.id,message||null]);
    await pool.execute("INSERT INTO audit_events(actor_user_id,event_type,target_user_id,details) VALUES(?,?,?,?)",[req.user.id,"DONOR_CONTACT_REQUESTED",donorId,`Contact request #${r.insertId} created`]);
    res.status(201).json({id:r.insertId,message:"Contact request sent. The donor must accept before their phone number is shared."});
  }catch(e){next(e);}
});
app.get("/api/contact-requests",requireAuth,async(req,res,next)=>{
  try{
    const [rows]=await pool.execute(`SELECT cr.id,cr.message,cr.status,cr.created_at,cr.responded_at,
      d.id AS donor_id,d.name AS donor_name,d.city AS donor_city,
      r.id AS requester_id,r.name AS requester_name,r.city AS requester_city,
      CASE WHEN cr.status='Accepted' AND cr.requester_user_id=? THEN d.phone ELSE NULL END AS donor_phone
      FROM donor_contact_requests cr JOIN users d ON d.id=cr.donor_user_id JOIN users r ON r.id=cr.requester_user_id
      WHERE cr.donor_user_id=? OR cr.requester_user_id=? ORDER BY cr.created_at DESC LIMIT 100`,[req.user.id,req.user.id,req.user.id]);
    res.json(rows);
  }catch(e){next(e);}
});
app.patch("/api/contact-requests/:id",requireAuth,async(req,res,next)=>{
  try{
    const id=Number(req.params.id),status=req.body.status;
    if(!Number.isInteger(id)||id<1||!['Accepted','Declined','Cancelled'].includes(status))return res.status(400).json({error:"Invalid contact request action."});
    const [rows]=await pool.execute("SELECT donor_user_id,requester_user_id,status FROM donor_contact_requests WHERE id=?",[id]);
    if(!rows.length)return res.status(404).json({error:"Contact request not found."});
    const row=rows[0];
    if(status==='Cancelled' ? Number(row.requester_user_id)!==Number(req.user.id) : Number(row.donor_user_id)!==Number(req.user.id))return res.status(403).json({error:"You cannot update this contact request."});
    if(row.status!=='Pending')return res.status(409).json({error:"This contact request has already been handled."});
    await pool.execute("UPDATE donor_contact_requests SET status=?,responded_at=CURRENT_TIMESTAMP WHERE id=?",[status,id]);
    await pool.execute("INSERT INTO audit_events(actor_user_id,event_type,target_user_id,details) VALUES(?,?,?,?)",[req.user.id,`DONOR_CONTACT_${status.toUpperCase()}`,status==='Cancelled'?row.donor_user_id:row.requester_user_id,`Contact request #${id}`]);
    res.json({message:`Contact request ${status.toLowerCase()}.`});
  }catch(e){next(e);}
});
app.get("/api/banks/:id/inventory",requireAuth,async(req,res,next)=>{
  try{
    const bankId=Number(req.params.id);
    const [rows]=await pool.execute(`SELECT i.blood_group,i.component,i.units,i.updated_at,b.name AS bank_name,b.verified
      FROM inventory i JOIN blood_banks b ON b.id=i.bank_id WHERE i.bank_id=? AND b.verified=1 ORDER BY i.blood_group,i.component`,[bankId]);
    res.json(rows);
  }catch(e){next(e);}
});

app.get("/api/dashboard",requireAuth,async(req,res,next)=>{
  try{
    const [[{donors}]] = await pool.query("SELECT COUNT(*) AS donors FROM donor_profiles d JOIN donor_health_disclosures h ON h.donor_user_id=d.user_id WHERE d.available=1 AND d.consent_to_contact=1 AND h.screening_status='Approved'");
    const [[{banks}]] = await pool.query("SELECT COUNT(*) AS banks FROM blood_banks WHERE verified=1");
    const [[{openRequests}]] = await pool.query("SELECT COUNT(*) AS openRequests FROM blood_requests WHERE status IN ('Open','Coordinating')");
    res.json({donors,banks,openRequests});
  }catch(e){next(e);}
});
app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,database:"connected"});}catch{res.status(503).json({ok:false,database:"unavailable"});}});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Server error. Check server configuration and database connection."});});
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`HelpBridge running at http://localhost:${port}`));

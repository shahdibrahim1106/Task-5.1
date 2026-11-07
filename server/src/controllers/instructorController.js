import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================
const PUBLIC_FIELDS = 'name department role';
function publicInstructor(u) {
  return { id: u._id.toString(), name: u.name, email: u.email, createdAt: u.createdAt };
}
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
    apiKey: doc.apiKey,
    privateEmail: doc.privateEmail,
    privatePhone: doc.privatePhone
  };
}
 const loginschema = Joi.object({
      username: Joi.string().trim.min(1).max(100).required(),
      password: Joi.string().min(1).max(100).required()
    });
const searchschema = Joi.object({
      name: Joi.string().trim().max(100),
      department: Joi.string().trim().max(100)
    });
// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });
 
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');
    const ok = instructor && (await bcrypt.compare(value.password, instructor.password));
 
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
    // ⚠️ VULNERABLE (NoSQL injection): `username` and `password` are placed
    // directly into the query. Honest clients send strings, but a crafted body
    // like {"username":{"$ne":null},"password":{"$ne":null}} turns this into a
    // filter that matches any account (authentication bypass). With
    // {"password":{"$regex":"^S"}} the success/failure response becomes an
    // oracle for extracting the stored password one character at a time.
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // ⚠️ VULNERABLE (NoSQL injection): the entire query string is used as the
    // MongoDB filter and full documents (incl. password / apiKey / private
    // contact info) are returned. Examples of what this allows:
    //   ?name=Smith                     -> intended, honest use
    //   ?role[$ne]=instructor           -> operator injection, leaks superadmin
    //   ?username[$regex]=^admin        -> regex enumeration
    //   ?$where=this.password.length>10 -> server-side JavaScript execution
    const { value, error } = searchSchema.validate(req.query, { stripUnknown: true });
    if (error) return res.status(400).json({ message: error.message });
    const filter = {};
    if (value.name) filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    if (value.department) filter.department = { $regex: escapeRegex(value.department), $options: 'i' };
 
    const instructors = await Instructor.find(filter)
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }

}

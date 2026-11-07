import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER (hardened against NoSQL injection)
// =============================================================================
//  Defence layers:
//   1. express-mongo-sanitize (app.js) strips any `$`/`.` keys from body/query.
//   2. Joi enforces TYPES (plain strings only) and an allow-list of fields.
//   3. Passwords are bcrypt-hashed (model hook) and compared in code, never
//      placed inside a query filter, so there is no regex/oracle to abuse.
//   4. Secret fields are `select:false` in the model and never serialised.
// =============================================================================

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(50).required(),
  password: Joi.string().min(1).max(128).required()
}).unknown(false);

const searchSchema = Joi.object({
  name: Joi.string().trim().max(100).allow(''),
  department: Joi.string().trim().max(60).allow(''),
  role: Joi.string().valid('instructor', 'superadmin')
}).unknown(false);

// Only PUBLIC fields ever leave the server.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Pre-computed hash so a missing user costs the same time as a wrong password.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const { username, password } = value;

    // Look up by username ONLY (a validated string), then compare the hash.
    const instructor = await Instructor.findOne({ username }).select('+password');
    const hash = instructor ? instructor.password : DUMMY_HASH;
    const ok = await bcrypt.compare(password, hash);

    if (!instructor || !ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
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
    // Keep only allow-listed keys whose value is a plain string. Anything else
    // (objects like {$ne:..}, arrays, unknown keys such as $where) is dropped.
    const params = {};
    for (const key of ['name', 'department', 'role']) {
      if (typeof req.query[key] === 'string') params[key] = req.query[key];
    }

    const { value, error } = searchSchema.validate(params);
    if (error) {
      return res.status(400).json({ message: 'Invalid search parameters' });
    }

    const filter = {};
    if (value.name) filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    if (value.department) filter.department = value.department;
    if (value.role) filter.role = value.role;

    const instructors = await Instructor.find(filter)
      .select('name username department role')
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}

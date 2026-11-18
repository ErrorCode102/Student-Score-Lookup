const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const SECRET = process.env.ADMIN_SECRET || 'vercel-supabase-secret-key-2026';

function verifyToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  if (sig !== expectedSig) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now();
  } catch {
    return false;
  }
}

function getSupabase() {
  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !key) {
    throw new Error('ยังไม่ได้ตั้งค่า SUPABASE_URL หรือ SUPABASE_SERVICE_ROLE_KEY ใน Vercel Environment Variables');
  }
  return createClient(url, key);
}

module.exports = async function handler(req, res) {
  try {
    const supabase = getSupabase();

    // ตรวจสอบสถานะการเชื่อมต่อ Vercel <-> Supabase
    if (req.method === 'GET' && req.query.health === '1') {
      const { error } = await supabase.from('student_scores').select('id').limit(1);
      if (error) return res.status(500).json({ connected: false, error: error.message });
      return res.status(200).json({ connected: true });
    }

    // GET: ค้นหารายบุคคล (สำหรับ User) หรือดึงทั้งหมด (เฉพาะ Admin)
    if (req.method === 'GET') {
      const studentId = (req.query.student_id || '').trim();

      if (studentId) {
        const { data, error } = await supabase
          .from('student_scores')
          .select('*')
          .eq('student_id', studentId)
          .order('id', { ascending: true });

        if (error) return res.status(500).json({ error: error.message });
        return res.status(200).json({ data });
      }

      // ถ้าไม่ระบุ student_id ต้องเป็น Admin เท่านั้นจึงจะดูข้อมูลทั้งหมดได้
      if (!verifyToken(req.headers.authorization)) {
        return res.status(403).json({ error: 'เฉพาะผู้ดูแลระบบ (Admin) เท่านั้นที่เข้าถึงข้อมูลทั้งหมดได้' });
      }

      const { data, error } = await supabase
        .from('student_scores')
        .select('*')
        .order('id', { ascending: false });

      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json({ data });
    }

    // ตรวจสอบสิทธิ์ Admin สำหรับ Insert / Edit / Delete
    if (!verifyToken(req.headers.authorization)) {
      return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ Admin ก่อนทำรายการ' });
    }

    // POST: เพิ่มข้อมูล (Insert)
    if (req.method === 'POST') {
      const { student_id, subject, score, pic } = req.body || {};
      const numScore = Number(score);
      if (!student_id || !subject || isNaN(numScore) || numScore < 0 || numScore > 100) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง (คะแนนต้องอยู่ระหว่าง 0 - 100)' });
      }

      const { data, error } = await supabase
        .from('student_scores')
        .insert([{
          student_id: String(student_id).trim(),
          subject: String(subject).trim(),
          score: numScore,
          pic: pic ? String(pic).trim() : null
        }])
        .select();

      if (error) return res.status(500).json({ error: error.message });
      return res.status(201).json({ data: data[0] });
    }

    // PUT: แก้ไขข้อมูล (Edit)
    if (req.method === 'PUT') {
      const { id, student_id, subject, score, pic } = req.body || {};
      const numScore = Number(score);
      if (!id || !student_id || !subject || isNaN(numScore) || numScore < 0 || numScore > 100) {
        return res.status(400).json({ error: 'ข้อมูลสำหรับแก้ไขไม่ถูกต้อง' });
      }

      const { data, error } = await supabase
        .from('student_scores')
        .update({
          student_id: String(student_id).trim(),
          subject: String(subject).trim(),
          score: numScore,
          pic: pic ? String(pic).trim() : null
        })
        .eq('id', id)
        .select();

      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json({ data: data[0] });
    }

    // DELETE: ลบข้อมูล (Delete)
    if (req.method === 'DELETE') {
      const id = req.query.id;
      if (!id) return res.status(400).json({ error: 'ไม่พบรหัสรายการที่ต้องการลบ' });

      const { error } = await supabase
        .from('student_scores')
        .delete()
        .eq('id', id);

      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

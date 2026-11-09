"""Automatic tests.  Run:  python tests.py
Shows that the security rules really work (access control, encryption,
verification, lockout, double-booking, tamper detection)."""
import os
import re
import sqlite3
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.environ["DATA_DIR"] = TMP  # tests use their own database and keys

import app as A  # noqa: E402

A.init_db()
SENT = []
A.send_mail = lambda to, subject, body: SENT.append((to, subject, body))


def fresh_client():
    c = A.app.test_client()
    html = c.get("/").get_data(as_text=True)
    return c, re.search(r'name="csrf" content="(\w+)"', html).group(1)


def post(c, tok, path, **json):
    return c.post(path, json=json, headers={"X-CSRF-Token": tok})


def day():
    return A.open_days()[0]


def book(c, tok, start=540, program="BS Accountancy", email="juan@ua.edu.ph", sno="20260123"):
    post(c, tok, "/api/send-code", email=email)
    code = re.search(r"code is (\d{6})", SENT[-1][2]).group(1)
    assert post(c, tok, "/api/verify-code", email=email, code=code).get_json().get("ok")
    return post(c, tok, "/api/book", name="Juan Dela Cruz", student_no=sno, section="3A",
                program=program, email=email, phone="09123456789", service="Counseling",
                day=day(), start=start, note="Need advice", consent=True)


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()) as out:
            A.seed()
        cls.pw = dict(re.findall(r"^\s+(\w+)\s+Ms\..*password: (\S+)$", out.getvalue(), re.M))

    def login(self, user, pw):
        c, tok = fresh_client()
        r = c.post("/staff/login", data={"username": user, "password": pw, "_csrf": tok})
        return c, tok, r

    def test_1_staff_pages_blocked_for_students(self):
        c, _ = fresh_client()
        self.assertEqual(c.get("/staff").status_code, 403)
        self.assertEqual(c.get("/receipt/GO-AAAAA").status_code, 403)

    def test_2_booking_is_encrypted_and_needs_verification(self):
        c, tok = fresh_client()
        bad = post(c, tok, "/api/book", name="X Y", student_no="20260999", section="1A",
                   program="BS Nursing", email="x@ua.edu.ph", phone="09123456789",
                   service="Counseling", day=day(), start=540, note="", consent=True)
        self.assertEqual(bad.status_code, 400)  # email not verified
        r = book(c, tok, start=570)
        self.assertEqual(r.status_code, 200)
        raw = sqlite3.connect(A.DB_PATH).execute("SELECT enc, id_hash FROM appointments").fetchall()
        blob = " ".join(x[0] + x[1] for x in raw)
        for secret in ("Juan", "20260123", "juan@ua.edu.ph", "09123456789", "Need advice"):
            self.assertNotIn(secret, blob)  # nothing readable in the database

    def test_3_wrong_code_rejected(self):
        c, tok = fresh_client()
        post(c, tok, "/api/send-code", email="a@ua.edu.ph")
        r = post(c, tok, "/api/verify-code", email="a@ua.edu.ph", code="000000")
        self.assertEqual(r.status_code, 400)

    def test_4_double_booking_blocked(self):
        c, tok = fresh_client()
        self.assertEqual(book(c, tok, start=600, sno="20260111").status_code, 200)
        c2, tok2 = fresh_client()
        self.assertEqual(book(c2, tok2, start=600, sno="20260222").status_code, 409)

    def test_5_counselors_see_only_their_students(self):
        c, tok = fresh_client()
        ref = book(c, tok, start=660, program="BS Nursing", sno="20260333").get_json()["ref"]
        paige, _, _ = self.login("paige", self.pw["paige"])
        page = paige.get("/staff").get_data(as_text=True)
        self.assertIn("Juan Dela Cruz", page)
        ptok = re.search(r'name="csrf" content="(\w+)"', page).group(1)  # new token after login
        lorna, _, _ = self.login("lorna", self.pw["lorna"])
        page = lorna.get("/staff").get_data(as_text=True)
        self.assertNotIn(ref, page)
        ltok = re.search(r'name="csrf" content="(\w+)"', page).group(1)
        r = lorna.post(f"/staff/appointments/{ref}/confirm", data={"_csrf": ltok})
        self.assertEqual(r.status_code, 403)  # wrong counselor
        paige.post(f"/staff/appointments/{ref}/confirm", data={"_csrf": ptok})
        self.assertIn("Confirmed", c.get(f"/check?ref={ref}").get_data(as_text=True))

    def test_6_lockout_after_5_wrong_passwords(self):
        c, tok = fresh_client()
        for _ in range(5):
            c.post("/staff/login", data={"username": "mica", "password": "wrong", "_csrf": tok})
        r = c.post("/staff/login", data={"username": "mica", "password": self.pw["mica"], "_csrf": tok})
        self.assertIn("locked", r.get_data(as_text=True))

    def test_7_tampering_detected(self):
        c, tok = fresh_client()
        ref = book(c, tok, start=720 + 60, program="BS HM", sno="20260444").get_json()["ref"]
        db = sqlite3.connect(A.DB_PATH)
        enc = db.execute("SELECT enc FROM appointments WHERE ref=?", (ref,)).fetchone()[0]
        db.execute("UPDATE appointments SET enc=? WHERE ref=?", (("A" if enc[5] != "A" else "B").join([enc[:5], enc[6:]]), ref))
        db.commit()
        maria, _, _ = self.login("maria", self.pw["maria"])
        self.assertIn("integrity check", maria.get("/staff").get_data(as_text=True))

    def test_9_idea_official_test_vector(self):
        import idea_crypto as I
        key = bytes.fromhex("00010002000300040005000600070008")
        ct = I.crypt_block(bytes.fromhex("0000000100020003"), I.expand_key(key))
        self.assertEqual(ct.hex().upper(), "11FBED2B01986DE5")
        self.assertEqual(I.crypt_block(ct, I.invert_key(I.expand_key(key))).hex(), "0000000100020003")

    def test_8_csrf_required(self):
        c, _ = fresh_client()
        self.assertEqual(c.post("/api/send-code", json={"email": "a@ua.edu.ph"}).status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)

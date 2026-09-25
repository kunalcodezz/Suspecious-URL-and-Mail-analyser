"""Unit tests for IOC Extractor, defanging, and export formatting."""

import unittest
from analyzers.ioc_extractor import IOCExtractor


class TestIOCExtractor(unittest.TestCase):
    def test_extraction_all_types(self):
        sample_text = """
        Alert report:
        Host infected: 192.168.1.100 and IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        Malicious beacon: https://c2-malware.evil.com/payload.bin
        Attacker email: dropzone@darknet.ru
        Attacker domain: secure-phish.net
        Dropped file hashes:
        MD5: e4d909c290d0fb1ca068ffaddf22cbd0
        SHA1: a9993e364706816aba3e25717850c26c9cd0d89d
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        iocs = IOCExtractor.extract_from_text(sample_text)
        self.assertIn("192.168.1.100", iocs.ipv4)
        self.assertIn("https://c2-malware.evil.com/payload.bin", iocs.urls)
        self.assertIn("dropzone@darknet.ru", iocs.emails)
        self.assertIn("secure-phish.net", iocs.domains)
        self.assertIn("e4d909c290d0fb1ca068ffaddf22cbd0", iocs.md5)
        self.assertIn("a9993e364706816aba3e25717850c26c9cd0d89d", iocs.sha1)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", iocs.sha256)

    def test_defanging(self):
        raw = "http://bad.domain.com/login"
        defanged = IOCExtractor.defang(raw)
        self.assertEqual(defanged, "hxxp://bad[.]domain[.]com/login")

        ip_raw = "1.2.3.4"
        self.assertEqual(IOCExtractor.defang(ip_raw), "1[.]2[.]3[.]4")

        email_raw = "test@phish.com"
        self.assertEqual(IOCExtractor.defang(email_raw), "test[@]phish[.]com")

    def test_export_formats(self):
        sample = "Check 10.10.10.10 and https://bad.org"
        iocs = IOCExtractor.extract_from_text(sample)
        
        json_out = iocs.to_json()
        self.assertIn('"ipv4": [', json_out)
        self.assertIn("10.10.10.10", json_out)

        csv_out = iocs.to_csv()
        self.assertIn("ioc_type,value", csv_out)
        self.assertIn("ipv4,10.10.10.10", csv_out)

        txt_out = iocs.to_txt()
        self.assertIn("[IPV4]", txt_out)
        self.assertIn("10.10.10.10", txt_out)


if __name__ == "__main__":
    unittest.main()

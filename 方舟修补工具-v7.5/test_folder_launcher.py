from pathlib import Path
import contextlib,io,subprocess,tempfile,unittest
from unittest.mock import patch
import start

ROOT=Path(__file__).resolve().parent

class FolderWorkflowTests(unittest.TestCase):
    def temp(self):return tempfile.TemporaryDirectory(dir=ROOT)
    def test_no_ipa_stops(self):
        with self.temp() as d,patch('start.subprocess.run') as run,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(start.main(d),2);run.assert_not_called()
    def test_multiple_ipas_stop(self):
        with self.temp() as d,patch('start.subprocess.run') as run,contextlib.redirect_stdout(io.StringIO()):
            p=Path(d);(p/'a.ipa').touch();(p/'b.IPA').touch()
            self.assertEqual(start.main(p),2);run.assert_not_called()
    def test_output_subfolder_ignored_and_failure_returned(self):
        with self.temp() as d,patch('start.subprocess.run',return_value=subprocess.CompletedProcess([],2)) as run,contextlib.redirect_stdout(io.StringIO()):
            p=Path(d);(p/'原包 with spaces.IPA').touch();(p/'output').mkdir();(p/'output/old.ipa').touch()
            (p/'kit').mkdir();(p/'kit/payload.zip').touch()
            self.assertEqual(start.main(p),2)
            args=run.call_args.args[0]
            self.assertEqual(Path(args[5]),p/'原包 with spaces.IPA')
            self.assertEqual(Path(args[7]).parent,p/'output')
            self.assertTrue(args[7].endswith('-unsigned.ipa'))
            self.assertEqual(run.call_args.kwargs['cwd'],str(p))
    def test_real_launcher_subprocess_creates_output(self):
        with self.temp() as d,contextlib.redirect_stdout(io.StringIO()):
            p=Path(d);(p/'原包.ipa').touch();(p/'kit').mkdir();(p/'kit/payload.zip').touch()
            # Stub only the expensive patcher; exercise real subprocess/path handling.
            (p/'arkpatch_decrypted.py').write_text("import pathlib,sys\np=pathlib.Path(sys.argv[4]);p.parent.mkdir();p.write_bytes(b'TEST ONLY')\n",encoding='utf-8')
            self.assertEqual(start.main(p),0)
            files=list((p/'output').glob('*.ipa'))
            self.assertEqual(len(files),1);self.assertEqual(files[0].read_bytes(),b'TEST ONLY')

if __name__=='__main__':unittest.main()

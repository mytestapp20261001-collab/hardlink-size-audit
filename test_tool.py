import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def test_deduplicates_inodes_and_cli(self):
        p=self.root/'a';p.write_bytes(b'abc');os.link(p,self.root/'b');(self.root/'c').write_bytes(b'abc')
        r=tool.audit(self.root,list_groups=True);s=r['summary'];self.assertEqual(s['logical_bytes'],9);self.assertEqual(s['inode_unique_bytes'],6);self.assertEqual(s['hardlink_groups'],1);self.assertEqual(s['hardlink_duplicate_logical_bytes'],3);self.assertEqual(self.call(self.root)[0],0)
    def test_outside_links_policy(self):
        d=self.root/'scan';d.mkdir();(d/'a').write_text('x');os.link(d/'a',self.root/'outside')
        self.assertEqual(tool.audit(d)['status'],'pass');self.assertIn('unaccounted_hardlinks',self.codes(tool.audit(d,require_contained_links=True)))
    def test_budget_and_cli(self):
        (self.root/'a').write_text('xxxx');self.assertIn('logical_byte_budget_exceeded',self.codes(tool.audit(self.root,max_logical_bytes=1)));self.assertEqual(self.call(self.root,'--max-logical-bytes','1')[0],1)
    def test_symlink_and_nonregular_exclusion(self):
        (self.root/'file').write_text('hello');(self.root/'link').symlink_to('file');os.mkfifo(self.root/'fifo')
        s=tool.audit(self.root)['summary'];self.assertEqual(s['logical_bytes'],5);self.assertEqual(s['non_regular_entries_excluded'],2)
    def test_sparse_allocation_is_distinct(self):
        with (self.root/'sparse').open('wb') as f:f.truncate(1048576)
        s=tool.audit(self.root)['summary'];self.assertEqual(s['logical_bytes'],1048576);self.assertEqual(s['reported_allocated_bytes'],os.stat(self.root/'sparse').st_blocks*512)
    def test_limits_and_permission(self):
        (self.root/'a').touch();(self.root/'b').touch();self.assertEqual(tool.audit(self.root,max_entries=1)['status'],'error');self.assertEqual(tool.audit(self.root,max_logical_bytes=0)['status'],'error')
        with mock.patch.object(tool,'walk',side_effect=PermissionError):self.assertEqual(tool.audit(self.root)['status'],'error')
    def test_empty(self):
        s=tool.audit(self.root)['summary'];self.assertEqual(s['logical_bytes'],0);self.assertEqual(s['reported_allocated_bytes'],0)

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()

if __name__=="__main__":unittest.main()

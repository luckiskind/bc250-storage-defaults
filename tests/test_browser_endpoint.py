"""A partial/hidden document or malformed marker must not become readiness."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':from browser_endpoint import validate_marker


@unittest.skipUnless(sys.platform=='linux','Desktop endpoint uses Linux ownership/terminal support')
class BrowserReadiness(unittest.TestCase):
    def marker(self):
        return dict(nonce='test',document_complete=True,visibility='visible',image_decoded=True,fonts_loaded=True,
            scripted_clicks=1,status_text='Ready 1',frames_waited=2,distinct_frame_timestamps=True,
            inner_width=1024,inner_height=768,page_elapsed_ms=123.5)

    def test_complete_marker_is_accepted(self):
        self.assertEqual(validate_marker(self.marker(),'test')['page_elapsed_ms'],123.5)

    def test_hidden_incomplete_or_wrong_owner_token_never_counts(self):
        for key,value in [('nonce','other'),('visibility','hidden'),('document_complete',False),
                ('image_decoded',False),('fonts_loaded',False),('distinct_frame_timestamps',False),('status_text','Waiting')]:
            with self.subTest(key=key):
                marker=self.marker();marker[key]=value
                with self.assertRaises(RuntimeError):validate_marker(marker,'test')

    def test_ambiguous_counts_extra_fields_and_invalid_clock_are_rejected(self):
        for key,value in [('scripted_clicks',True),('frames_waited',1),('inner_width',True),
                ('page_elapsed_ms',float('nan')),('page_elapsed_ms',float('inf')),('extra',1)]:
            with self.subTest(key=key,value=value):
                marker=self.marker();marker[key]=value
                with self.assertRaises(RuntimeError):validate_marker(marker,'test')


if __name__=='__main__':unittest.main()

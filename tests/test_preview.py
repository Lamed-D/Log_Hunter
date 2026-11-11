"""코드로 만든 내용만 사용해 미리보기와 읽기 상한을 검증합니다."""
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
import zlib

from log_hunter.core.preview import preview, PreviewSource, TEXT_READ


def png():
    def chunk(kind,data):
        return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0\xff\0\0'))+chunk(b'IEND',b'')


def gif():
    return b'GIF89a'+struct.pack('<HHBBB',1,1,0x80,0,0)+b'\0\0\0\xff\xff\xff'+b','+struct.pack('<HHHHB',0,0,1,1,0)+b'\x02\x02D\x01\0;'


def bmp():
    header=struct.pack('<IiiHHIIiiII',40,1,1,1,24,0,4,0,0,0,0)
    return b'BM'+struct.pack('<IHHI',58,0,0,54)+header+b'\0\0\xff\0'


def ico():
    dib=struct.pack('<IiiHHIIiiII',40,1,2,1,32,0,4,0,0,0,0)+b'\0\0\xff\xff'+bytes(4)
    return struct.pack('<HHHBBBBHHII',0,1,1,1,1,0,0,1,32,len(dib),22)+dib


def archive(files, compressed=True):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as z:
        for name,data in files.items(): z.writestr(name,data)
    return out.getvalue()


def named(name,data,**states):
    return PreviewSource(name,len(data),lambda offset,length:data[offset:offset+length],**states)


class PreviewTests(unittest.TestCase):
    def test_image_bytes_are_accepted_by_tk_when_available(self):
        try:
            import tkinter as tk
        except ImportError:
            self.skipTest('Tkinter 없음')
        try:
            root=tk.Tk();root.withdraw()
        except tk.TclError:
            self.skipTest('표시 환경 없음')
        try:
            for data in (png(),gif(),bmp(),ico()):
                result=preview(data)
                image=tk.PhotoImage(master=root,data=result.image_bytes,format=result.metadata['preview_format'])
                self.assertEqual((image.width(),image.height()),(1,1))
        finally:
            root.destroy()

    def test_text_encodings_control_characters_and_read_limit(self):
        for encoding in ('utf-8','utf-16','utf-16-be','cp949'):
            raw='한글 문서와 보고서\n'.encode(encoding)
            result=preview(named('한글.txt',raw))
            self.assertEqual(result.kind,'text',result.reason)
            self.assertEqual(result.text,'한글 문서와 보고서\n')
        calls=[]
        def read(offset,length): calls.append((offset,length));return b'A'*length
        result=preview(PreviewSource('large.txt',1024*1024,read))
        self.assertEqual(calls,[(0,TEXT_READ)])
        self.assertTrue(result.truncated)
        result=preview(('한글'*100+'\x01').encode('utf-8'))
        self.assertIn('\ufffd',result.text)
        self.assertTrue(preview(b'abc',seconds=0).errors)

    def test_empty_sparse_encrypted_compressed_unallocated_and_deleted(self):
        for flags in ({'sparse':True},{'encrypted':True},{'compressed':True},{'allocated':False}):
            calls=[]
            result=preview(PreviewSource('synthetic',4,lambda *args:calls.append(args),**flags))
            self.assertEqual(result.kind,'none')
            self.assertEqual(result.data_state,'unavailable')
            self.assertTrue(result.reason)
            self.assertEqual(calls,[])
        self.assertEqual(preview(b'').reason,'빈 파일')
        deleted=preview(named('deleted.txt',b'synthetic',in_use=False))
        self.assertEqual(deleted.data_state,'recovery_estimate')
        self.assertTrue(any('덮어' in warning for warning in deleted.warnings))

    def test_small_images_and_bmp_ico_png_conversion(self):
        for name,data in (('a.png',png()),('a.gif',gif()),('a.bmp',bmp()),('a.ico',ico())):
            result=preview(named(name,data))
            self.assertEqual(result.kind,'image',(name,result.reason))
            self.assertEqual((result.metadata['width'],result.metadata['height']),(1,1))
            self.assertFalse(result.extension_mismatch)
            if name.endswith(('.bmp','.ico')):
                encoded=result.image_bytes
                self.assertTrue(encoded.startswith(b'\x89PNG'))
                offset=encoded.index(b'IDAT');size=struct.unpack_from('>I',encoded,offset-4)[0]
                self.assertEqual(zlib.decompress(encoded[offset+4:offset+4+size]),b'\0\xff\0\0\xff')
        self.assertTrue(preview(named('위장.txt',png())).extension_mismatch)
        self.assertTrue(preview(named('위장.png',b'synthetic text')).extension_mismatch)

    def test_image_damage_and_inflation_bomb_are_bounded(self):
        for data in (png()[:20],gif()[:-1],bmp()[:-1],ico()[:-1]):
            result=preview(data)
            self.assertEqual(result.kind,'none')
            self.assertTrue(result.errors)
        data=bytearray(png());data[20]^=1
        self.assertTrue(preview(bytes(data)).errors)
        def chunk(kind,data):
            return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
        bomb=png()[:33]+chunk(b'IDAT',zlib.compress(b'X'*1024*1024))+chunk(b'IEND',b'')
        self.assertTrue(preview(bomb).errors)
        ancillary=png()[:-12]+chunk(b'zTXt',b'TEST\0\0'+zlib.compress(b'X'*1024*1024))+png()[-12:]
        result=preview(ancillary)
        self.assertEqual(result.kind,'image',result.reason)
        self.assertNotIn(b'zTXt',result.image_bytes)
        self.assertTrue(result.metadata['ancillary_metadata_removed'])

    def test_jpeg_dimensions_and_exif_are_metadata_only(self):
        model=b'TESTCAM-01\0'
        date=b'2024:01:01 10:00:00\0'
        tiff=b'II'+struct.pack('<HIH',42,8,2)+struct.pack('<HHII',0x110,2,len(model),38)
        tiff+=struct.pack('<HHII',0x8769,4,1,50)+bytes(4)+model+b'\0'
        tiff+=struct.pack('<HHHII',1,0x9003,2,len(date),68)+bytes(4)+date
        exif=b'Exif\0\0'+tiff
        raw=b'\xff\xd8\xff\xe1'+struct.pack('>H',len(exif)+2)+exif
        raw+=b'\xff\xc0'+struct.pack('>H',11)+b'\x08\0\x01\0\x01\x01\x01\x11\0'+b'\xff\xd9'
        result=preview(named('a.jpg',raw))
        self.assertEqual(result.kind,'metadata',result.reason)
        self.assertEqual(result.metadata['camera_model'],'TESTCAM-01')
        self.assertEqual(result.metadata['width'],1)
        self.assertEqual(result.metadata['date_time_original_raw'],'2024:01:01 10:00:00')
        self.assertFalse(result.metadata['timezone_known'])
        self.assertEqual(result.image_bytes,b'')

    def test_pdf_office_and_zip_metadata_text_and_no_extraction(self):
        pdf=b'%PDF-1.4\n<< /Count 1 /Title (TEST) >>\n<< /Length 18 >>\nstream\n(TEST text) Tj\nendstream\n%%EOF'
        result=preview(named('a.pdf',pdf))
        self.assertEqual(result.metadata['page_count_hint'],1)
        self.assertFalse(result.metadata['page_count_verified'])
        self.assertIn('TEST text',result.text)
        self.assertEqual(result.metadata['title'],'TEST')
        for member,extension in (('word/document.xml','docx'),('xl/workbook.xml','xlsx'),('ppt/presentation.xml','pptx')):
            files={member:'<root><t>한글 본문</t></root>'.encode(),
                   'docProps/core.xml':'<root><title>합성 문서</title><creator>alice</creator></root>'.encode()}
            if extension=='xlsx': files['xl/sharedStrings.xml']=files[member]
            if extension=='pptx': files['ppt/slides/slide1.xml']=files[member]
            result=preview(named('a.'+extension,archive(files)))
            self.assertEqual(result.signature_format,extension,result.reason)
            self.assertEqual(result.metadata['title'],'합성 문서')
            self.assertIn('한글 본문',result.text)
        result=preview(named('a.zip',archive({'../보고서.txt':b'synthetic'})))
        self.assertEqual(result.metadata['files'],['../보고서.txt'])
        self.assertEqual(result.image_bytes,b'')

    def test_zip_bomb_damage_and_xml_entities_are_rejected(self):
        for data in (archive({'a':b'0'*100000}),archive({'word/document.xml':b'<!DOCTYPE a [<!ENTITY b "x">]><a>&b;</a>'}),
                     archive({'a':b'x'})[:-3]):
            result=preview(data)
            self.assertEqual(result.kind,'none')
            self.assertTrue(result.errors)
        data=bytearray(archive({'a':b'x'}));end=data.rfind(b'PK\x05\x06')
        struct.pack_into('<HH',data,end+8,513,513)
        self.assertTrue(preview(bytes(data)).errors)

    def test_hwp_compound_header_and_summary_metadata(self):
        from test_jumplist_streams import compound
        title='가짜 보고서\0'.encode('utf-16-le')
        value=struct.pack('<II',31,len(title)//2)+title
        section=struct.pack('<IIII',16+len(value),1,2,16)+value
        summary=b'\xfe\xff'+bytes(22)+struct.pack('<I',1)+bytes(16)+struct.pack('<I',48)+section
        header=b'HWP Document File'.ljust(32,b'\0')+struct.pack('<II',0x05000300,1)
        raw=compound({'FileHeader':header,'\x05HwpSummaryInformation':summary})
        result=preview(named('보고서.hwp',raw))
        self.assertEqual(result.signature_format,'hwp',result.reason)
        self.assertEqual(result.metadata['version'],'.'.join(str(part) for part in (5,0,3,0)))
        self.assertEqual(result.metadata['title'],'가짜 보고서')
        self.assertTrue(result.metadata['body_compressed'])

    def test_image_file_adapter_and_source_hash_remain_unchanged(self):
        from test_image import NTFSBuilder
        from log_hunter.image.browse import ImageBrowser
        builder=NTFSBuilder();parent=builder.makedirs('Evidence')
        builder.add_file(parent,'보고서.txt','한글 본문'.encode('utf-8'),mode='resident')
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'synthetic.dd';p.write_bytes(builder.build())
            before=hashlib.sha256(p.read_bytes()).digest();browser=ImageBrowser(p)
            try:
                source=browser.open_file(0,('Evidence','보고서.txt'))
                result=preview(source)
                self.assertEqual(result.text,'한글 본문',result.reason)
                self.assertEqual(result.data_state,'actual')
                source.record.in_use=False
                self.assertEqual(preview(source).data_state,'recovery_estimate')
            finally: browser.close()
            self.assertEqual(hashlib.sha256(p.read_bytes()).digest(),before)

    def test_hex_fallback_and_reader_range_failures(self):
        result=preview(bytes(range(32)))
        self.assertEqual(result.kind,'hex')
        self.assertIn('00000000',result.text)
        self.assertTrue(preview(PreviewSource('bad',1,lambda *_:b'too large')).errors)
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'보고서.txt';p.write_text('가짜 문서',encoding='utf-8')
            before=p.read_bytes();self.assertEqual(preview(p).text,'가짜 문서');self.assertEqual(p.read_bytes(),before)

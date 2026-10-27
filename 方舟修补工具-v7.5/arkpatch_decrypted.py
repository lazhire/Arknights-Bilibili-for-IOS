"""Decrypted-only, version-locked Arknights IPA patcher. Standard library only; never decrypts or signs."""
from pathlib import Path, PurePosixPath
import argparse, copy, hashlib, json, plistlib, shutil, struct, sys, uuid, zipfile

TOOL_BUILD = 'v7.5-2.7.81-flexible-input'
LOCKED_MANIFEST_SHA256 = '4b37a59b452b39c7a65de975e97657bc038119c65706ca7e557be05393d64173'

class PatchError(Exception): pass
def require(ok, message):
    if not ok: raise PatchError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def file_sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def safe_zip(z):
    names=z.namelist();require(len(names)==len(set(names)), 'Duplicate ZIP entries')
    for entry in z.infolist():
        n=entry.orig_filename
        p=PurePosixPath(n)
        require(not p.is_absolute() and '..' not in p.parts and '\\' not in n and ':' not in n and '\x00' not in n,'Unsafe ZIP entry')
    return names

def macho_slices(data):
    """Inspect every architecture; do not interpret cryptid=0 as proof of valid plaintext."""
    require(len(data)>=8,'Truncated Mach-O')
    if data[:4] in (b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf'):
        fat64=data[:4]==b'\xca\xfe\xba\xbf';n=struct.unpack_from('>I',data,4)[0]
        require(0<n<32,'Invalid fat architecture count');out=[]
        for i in range(n):
            pos=8+i*(32 if fat64 else 20)
            require(pos+(32 if fat64 else 20)<=len(data),'Truncated fat header')
            vals=struct.unpack_from('>IIQQII' if fat64 else '>IIIII',data,pos)
            offset,size=vals[2:4];require(offset+size<=len(data),'Invalid fat slice')
            out.extend(macho_slices(data[offset:offset+size]))
        return out
    is64=data[:4]==b'\xcf\xfa\xed\xfe'
    require(is64 or data[:4]==b'\xce\xfa\xed\xfe','Unsupported executable format')
    header=32 if is64 else 28;require(len(data)>=header,'Truncated Mach header')
    cpu,sub=struct.unpack_from('<II',data,4);n,size=struct.unpack_from('<II',data,16)
    require(header+size<=len(data) and n<=size//8,'Invalid load commands')
    pos=header;r={'cpu':cpu,'subtype':sub,'cryptids':[],'uuid':None,'size':len(data),'sha256':sha(data)}
    for _ in range(n):
        require(pos+8<=header+size,'Truncated load command');cmd,span=struct.unpack_from('<II',data,pos)
        require(span>=8 and pos+span<=header+size,'Invalid load command size')
        if cmd==0x1b:
            require(span>=24,'Truncated UUID');r['uuid']=str(uuid.UUID(bytes=data[pos+8:pos+24]))
        if cmd in (0x21,0x2c):
            require(span>=20,'Truncated encryption command');r['cryptids'].append(struct.unpack_from('<I',data,pos+16)[0])
        pos+=span
    require(pos==header+size,'Load command size mismatch')
    return [r]

def inspect_ipa(path, include_hash=True):
    with zipfile.ZipFile(path) as z:
        names=safe_zip(z)
        main=[n for n in names if n.startswith('Payload/') and n.endswith('.app/Info.plist') and n.count('/')==2]
        require(len(main)==1,'Expected one top-level app bundle')
        info=plistlib.loads(z.read(main[0]));app=main[0][:-len('Info.plist')]
        binaries={app+info['CFBundleExecutable']}
        for n in names:
            if n.startswith(app) and n.endswith('/Info.plist') and ('.framework/' in n or '.appex/' in n):
                d=plistlib.loads(z.read(n))
                if d.get('CFBundleExecutable'):binaries.add(n.rsplit('/',1)[0]+'/'+d['CFBundleExecutable'])
            if n.startswith(app+'Frameworks/') and n.endswith('.dylib'):binaries.add(n)
        result={'app_root':app,'bundle_id':info.get('CFBundleIdentifier'),'version':info.get('CFBundleShortVersionString'),'build':str(info.get('CFBundleVersion')),
                'binaries':{n:macho_slices(z.read(n)) for n in sorted(binaries)}}
        result['encrypted']=any(any(s['cryptids']) for slices in result['binaries'].values() for s in slices)
    if include_hash:result['ipa_sha256']=file_sha(path)
    return result

def strip_entry(name):
    # These files belong to the original store/signature, not reusable sideload signatures.
    parts=PurePosixPath(name).parts
    return not name.startswith('Payload/') or 'SC_Info' in parts or '_CodeSignature' in parts or name.endswith('/embedded.mobileprovision')

def load_kit(path, require_payload=True):
    root=Path(path)
    require((root/'manifest.json').is_file(),'MISSING_PROFILE: retain kit/manifest.json beside this script')
    raw=(root/'manifest.json').read_bytes()
    require(sha(raw)==LOCKED_MANIFEST_SHA256,'LOCKED_PROFILE: only the pinned v7.5 / 2.7.81 build 71 profile is supported')
    m=json.loads(raw)
    require(m['schema']==1 and m['revision']=='7.5' and m['version']=='2.7.81' and m['build']=='71','Unsupported profile')
    if require_payload:
        require((root/'payload.zip').is_file(),'MISSING_PAYLOAD: the source-only distribution excludes proprietary SDK components; supply your authorized matching local kit/payload.zip')
        require(file_sha(root/'payload.zip')==m['payload_sha256'],'Patch payload checksum mismatch')
    return root,m

def validate_input(s,m):
    require(not s['encrypted'],'ENCRYPTED_INPUT: decrypted IPA required; this tool does not decrypt')
    for k in ['bundle_id','version','build','app_root']:
        require(s[k]==m[k],'UNSUPPORTED_LAYOUT: input '+k+' mismatch; report this version in Issues')
    for n,e in m['host_binaries'].items():
        slices=s['binaries'].get(n,[])
        require(len(slices)==1 and slices[0]['cpu']==0x100000c and slices[0]['uuid']==e['uuid'] and not any(slices[0]['cryptids']),
                'UNSUPPORTED_LAYOUT: executable architecture/UUID mismatch: '+n)
    return s

def apply_binary_ranges(raw,spec):
    edited=bytearray(raw)
    for change in spec['ranges']:
        off=change['offset'];before=bytes.fromhex(change['before']);after=bytes.fromhex(change['after'])
        require(0<=off and off+len(before)<=len(raw) and len(before)==len(after) and raw[off:off+len(before)]==before,
                'UNSUPPORTED_LAYOUT: binary patch preimage mismatch; already patched or incompatible build')
        edited[off:off+len(after)]=after
    return bytes(edited)

def patch(input_path, output_path, kit_path):
    source=Path(input_path).resolve();target=Path(output_path).resolve();root,m=load_kit(kit_path)
    require(source!=target,'Input/output must be different')
    require(not target.exists(),'Refusing to overwrite output')
    partial=target.with_suffix(target.suffix+'.partial');require(not partial.exists(),'Partial output already exists')
    s=inspect_ipa(source, include_hash=False)
    validate_input(s,m)
    target.parent.mkdir(parents=True,exist_ok=True)
    report={'input_hash_allowlist_used':False,'revision':m['revision'],'encrypted_input':s['encrypted'],'decrypted_donor_used':False,
            'decryption_performed':False,'signed':False,'runtime_tested':False,'removed_entries':[],'modified_entries':[],'added_entries':[]}
    try:
        with zipfile.ZipFile(source) as zin,zipfile.ZipFile(source) as dz,zipfile.ZipFile(root/'payload.zip') as kit:
            overlay={n:kit.read(n) for n in safe_zip(kit) if not n.endswith('/')}
            require({n:sha(b) for n,b in overlay.items()}==m['payload_entries'],'Payload entry fingerprints mismatch')
            for n in overlay:require(n.startswith(m['app_root']),'Patch outside main app')
            host_overlay={}
            for n,e in m['host_binaries'].items():
                raw=dz.read(n)
                if n in m['binary_patches']:
                    raw=apply_binary_ranges(raw,m['binary_patches'][n])
                host_overlay[n]=raw
            overlay.update(host_overlay)
            info=plistlib.loads(overlay[m['app_root']+'Info.plist'])
            require(info['CFBundleIdentifier']==m['bundle_id'] and 'ABPackagingRevision' in info,'Invalid patched app metadata')
            # Inspect every output executable, including bridge, rather than only clearing flags.
            for n,raw in overlay.items():
                if n in host_overlay or n.endswith('.dylib'):
                    require(not any(any(x['cryptids']) for x in macho_slices(raw)),'Encrypted output executable')
            written=set();unchanged={}
            print('Verified decrypted input, version, UUIDs and patch preimages (no source hash allowlist). Packaging...',flush=True)
            with zipfile.ZipFile(partial,'w',zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as zout:
                for original in zin.infolist():
                    n=original.filename
                    if strip_entry(n):report['removed_entries'].append(n);continue
                    entry=copy.copy(original);entry._compresslevel=1
                    if n in overlay:
                        data=overlay[n];zout.writestr(entry,data)
                        if (original.CRC,original.file_size)!=(zout.getinfo(n).CRC,len(data)):report['modified_entries'].append(n)
                    elif original.is_dir():zout.writestr(entry,b'')
                    else:
                        with zin.open(original) as inp,zout.open(entry,'w',force_zip64=True) as out:shutil.copyfileobj(inp,out,8*1024*1024)
                        unchanged[n]=(original.CRC,original.file_size)
                    written.add(n)
                for n in sorted(set(overlay)-written):
                    entry=zipfile.ZipInfo(n);entry.create_system=3;entry.compress_type=zipfile.ZIP_DEFLATED;entry._compresslevel=1
                    entry.external_attr=(0o100755 if n.endswith('.dylib') else 0o100644)<<16
                    zout.writestr(entry,overlay[n]);report['added_entries'].append(n)
            print('Verifying ZIP integrity and preserved resources...',flush=True)
            with zipfile.ZipFile(partial) as out:
                require(out.testzip() is None,'ZIP CRC verification failed');safe_zip(out)
                require(set(out.namelist())==written|set(overlay),'Output inventory mismatch')
                for n,data in overlay.items():require(sha(out.read(n))==sha(data),'Output payload mismatch: '+n)
                for n,fingerprint in unchanged.items():require((out.getinfo(n).CRC,out.getinfo(n).file_size)==fingerprint,'Unexpected resource change: '+n)
            report.update(zip_crc_verified=True,preserved_source_files=len(unchanged),output_sha256=file_sha(partial),output_bytes=partial.stat().st_size)
        partial.rename(target)
        target.with_suffix('.report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({k:v for k,v in report.items() if not k.endswith('_entries')},ensure_ascii=True),flush=True)
        return report
    except BaseException:
        # Remove only this invocation's unfinished output; retain the input files.
        if partial.is_file():partial.unlink()
        raise

def main():
    if sys.version_info < (3,11):
        print('STOP: Python 3.11 or later is required',file=sys.stderr);return 2
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('inspect');a.add_argument('ipa');a.add_argument('--report')
    a=sub.add_parser('check');a.add_argument('ipa');a.add_argument('--kit',default=str(Path(__file__).resolve().parent/'kit'))
    a=sub.add_parser('patch');a.add_argument('ipa');a.add_argument('--output',required=True);a.add_argument('--kit',default=str(Path(__file__).resolve().parent/'kit'))
    args=p.parse_args()
    try:
        if args.command=='inspect':
            r=inspect_ipa(args.ipa);text=json.dumps(r,ensure_ascii=False,indent=2)
            if args.report:
                require(Path(args.report).resolve()!=Path(args.ipa).resolve(),'Report path must not overwrite input IPA')
                Path(args.report).write_text(text,encoding='utf-8')
            print(json.dumps(r,ensure_ascii=True))
        elif args.command=='check':
            _,m=load_kit(args.kit,require_payload=False)
            s=validate_input(inspect_ipa(args.ipa, include_hash=False),m)
            print(json.dumps({'layout_metadata_matches':True,'patch_preimages_checked':False,'input_hash_allowlist_used':False,'tool':TOOL_BUILD,'version':s['version'],'build':s['build'],'patch_revision':m['revision'],'runtime_tested':False},ensure_ascii=True))
        else:patch(args.ipa,args.output,args.kit)
    except (PatchError,ValueError,KeyError,OSError,struct.error,plistlib.InvalidFileException,zipfile.BadZipFile) as e:
        print('STOP: '+str(e),file=sys.stderr);return 2
    return 0
if __name__=='__main__':sys.exit(main())

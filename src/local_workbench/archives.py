"""Archive inventory and member capture without filesystem extraction."""
from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import json
import lzma
from pathlib import PurePosixPath
import stat
import struct
import tarfile
import time
import zipfile

from .errors import WorkbenchError
from .views import response_size


class LimitedReader:
    def __init__(self,source,limit,deadline):
        self.source,self.remaining,self.deadline=source,limit,deadline
    def read(self,size=-1):
        if time.monotonic()>self.deadline:
            raise WorkbenchError('archive_deadline','Archive scan exceeded its time budget.')
        size=self.remaining+1 if size is None or size<0 else min(size,self.remaining+1)
        data=self.source.read(size)
        self.remaining-=len(data)
        if self.remaining<0:
            raise WorkbenchError('archive_expansion_limit','Archive expanded beyond the declared read budget.')
        return data


class ArchiveTools:
    def __init__(self,store,files):
        self.store,self.files=store,files

    @staticmethod
    def _name(name):
        normalized=name.replace('\\','/')
        parts=PurePosixPath(normalized).parts
        return {'name':name,'unsafe_extraction_path':normalized.startswith('/') or '..' in parts
                or '\0' in name or (len(normalized)>1 and normalized[1]==':')}

    @staticmethod
    def _zip_preflight(source,max_members):
        source.seek(0,2);total=source.tell();source.seek(max(0,total-65557));tail=source.read(65557)
        end=tail.rfind(b'PK\x05\x06')
        if end<0 or end+22>len(tail):
            raise WorkbenchError('invalid_archive','ZIP end record is absent.')
        _,disk,start_disk,on_disk,count,directory_size,directory_offset,comment=struct.unpack_from('<4s4H2IH',tail,end)
        if end+22+comment!=len(tail) or disk or start_disk or on_disk!=count:
            raise WorkbenchError('unsupported_archive','Malformed or multi-volume ZIP is unsupported.')
        if count==65535 or directory_size==0xffffffff or directory_offset==0xffffffff:
            locator_offset=max(0,total-len(tail))+end-20
            if locator_offset<0:raise WorkbenchError('invalid_archive','Missing ZIP64 locator.')
            source.seek(locator_offset);locator=source.read(20)
            if len(locator)!=20 or locator[:4]!=b'PK\x06\x07':raise WorkbenchError('invalid_archive','Invalid ZIP64 locator.')
            _,zip_disk,record_offset,disks=struct.unpack('<4sIQI',locator)
            if zip_disk or disks!=1 or record_offset>total-56:raise WorkbenchError('unsupported_archive','Unsupported ZIP64 volume layout.')
            source.seek(record_offset);record=source.read(56)
            if len(record)!=56 or record[:4]!=b'PK\x06\x06':raise WorkbenchError('invalid_archive','Invalid ZIP64 end record.')
            count,directory_size,directory_offset=struct.unpack_from('<QQQ',record,32)
        if count>max_members:
            raise WorkbenchError('archive_member_limit','ZIP declares more members than this bounded inspection permits.',declared_members=count,limit=max_members)
        if directory_size>8*1024*1024 or directory_offset+directory_size>total:
            raise WorkbenchError('archive_metadata_limit','ZIP central directory exceeds the 8 MiB metadata budget or source length.')
        source.seek(0)

    @contextlib.contextmanager
    def _open(self,artifact_id,max_members,max_expanded):
        with self.store.reading(artifact_id) as source:
            magic=source.read(8);source.seek(0)
            if magic.startswith(b'PK'):
                self._zip_preflight(source,max_members)
                with zipfile.ZipFile(source) as archive:
                    entries=archive.infolist()
                    if len(entries)>max_members:raise WorkbenchError('archive_member_limit','Actual ZIP member count exceeds the limit.')
                    yield 'zip',archive,iter(entries)
                return
            with contextlib.ExitStack() as stack:
                if magic.startswith(b'\x1f\x8b'):decoded=stack.enter_context(gzip.GzipFile(fileobj=source))
                elif magic.startswith(b'BZh'):decoded=stack.enter_context(bz2.BZ2File(source))
                elif magic.startswith(b'\xfd7zXZ'):decoded=stack.enter_context(lzma.LZMAFile(source))
                else:decoded=source
                limited=LimitedReader(decoded,max_expanded+8*1024*1024,time.monotonic()+10)
                archive=stack.enter_context(tarfile.open(fileobj=limited,mode='r|'))
                yield 'tar',archive,iter(archive)

    def manifest(self,artifact_id,max_members=10000,max_expanded_bytes=268435456,max_bytes=8192):
        if type(max_members) is not int or not 1<=max_members<=50000 or type(max_expanded_bytes) is not int or not 1<=max_expanded_bytes<=512*1024*1024:
            raise WorkbenchError('invalid_range','Use members 1..50000 and expanded bytes 1..536870912.')
        if type(max_bytes) is not int or not 4096<=max_bytes<=262144:
            raise WorkbenchError('invalid_range','max_bytes must be 4096..262144.')
        summary={'source_artifact':artifact_id,'members':0,'declared_expanded_bytes':0,'duplicates':0,'unsafe_names':0,
                 'complete':True,'content_hashes_checked':False,'filesystem_extraction_performed':False}
        preview=[];seen=set()
        def records():
            try:
                with self._open(artifact_id,max_members,max_expanded_bytes) as (kind,archive,entries):
                    summary['archive_format']=kind
                    for index,member in enumerate(entries):
                        if index>=max_members:
                            raise WorkbenchError('archive_member_limit','TAR member budget reached; unvisited members are unknown.')
                        if kind=='zip':
                            size=member.file_size;mode=member.external_attr>>16
                            entry_type='directory' if member.is_dir() else 'symlink' if stat.S_ISLNK(mode) else 'file'
                            name=member.filename
                            record={**self._name(name),'type':entry_type,'bytes':size,'compressed_bytes':member.compress_size,
                                    'encrypted':bool(member.flag_bits&1)}
                        else:
                            size=member.size;name=member.name
                            entry_type='file' if member.isfile() else 'directory' if member.isdir() else 'symlink' if member.issym() else 'hardlink' if member.islnk() else 'special'
                            record={**self._name(name),'type':entry_type,'bytes':size,'link_target':member.linkname or None}
                        record.update(member_index=index,duplicate_name=name in seen)
                        seen.add(name)
                        summary['members']+=1;summary['declared_expanded_bytes']+=size
                        summary['duplicates']+=record['duplicate_name'];summary['unsafe_names']+=record['unsafe_extraction_path']
                        if len(preview)<10:preview.append(record)
                        yield record
                        if summary['declared_expanded_bytes']>max_expanded_bytes:
                            raise WorkbenchError('archive_expansion_limit','Declared expansion budget exceeded; remaining members were not inspected.')
            except (WorkbenchError,tarfile.TarError,zipfile.BadZipFile,OSError,EOFError,ValueError) as exc:
                summary.update(complete=False,unvisited_count='unknown')
                error=exc.as_dict()['error'] if isinstance(exc,WorkbenchError) else {'code':'invalid_archive','message':'Archive metadata could not be read.'}
                summary['error']=error
                yield {'kind':'coverage_gap','error':error}
        result=self.files._manifest(records(),'archive-manifest:'+artifact_id,summary)
        result.pop('page',None);result['preview']=preview
        while response_size(result)>max_bytes and result['preview']:result['preview']=result['preview'][:-1]
        if response_size(result)>max_bytes:raise WorkbenchError('response_budget','Archive identity metadata exceeds the result budget.',artifact_id=result['artifact_id'])
        return result

    def member(self,artifact_id,member_index,max_bytes=16*1024*1024):
        if type(member_index) is not int or not 0<=member_index<50000 or type(max_bytes) is not int or not 1<=max_bytes<=64*1024*1024:
            raise WorkbenchError('invalid_range','Use a member index below 50000 and capture limit up to 64 MiB.')
        try:
            with self._open(artifact_id,50000,256*1024*1024) as (kind,archive,entries):
                for index,member in enumerate(entries):
                    if index!=member_index:continue
                    regular=(not member.is_dir() and not stat.S_ISLNK(member.external_attr>>16)) if kind=='zip' else member.isfile()
                    name=member.filename if kind=='zip' else member.name
                    size=member.file_size if kind=='zip' else member.size
                    if not regular:raise WorkbenchError('not_regular_member','Only regular member bytes are captured; links are never followed.')
                    if size>max_bytes:raise WorkbenchError('archive_member_limit','Selected member exceeds its capture budget.',declared_bytes=size)
                    with archive.open(member) if kind=='zip' else archive.extractfile(member) as stream:
                        artifact=self.store.put_stream(LimitedReader(stream,max_bytes,time.monotonic()+10),f'archive-member:{artifact_id}:{index}')
                    return {'ok':True,'source_archive':artifact_id,'member_index':index,'member_name':name[:512],
                            'member_name_truncated':len(name)>512,'artifact':artifact,'filesystem_extraction_performed':False}
        except (tarfile.TarError,zipfile.BadZipFile,OSError,EOFError,ValueError,RuntimeError) as exc:
            raise WorkbenchError('archive_member_failed','Member is unavailable, encrypted, corrupt, or outside the read budget.') from exc
        raise WorkbenchError('member_not_found','No member has that index.')

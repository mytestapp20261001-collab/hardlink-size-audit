#!/usr/bin/env python3
"""Separate logical, inode-deduplicated, and stat-reported allocated regular-file bytes."""
import stat
from _support import InputError, Parser, Report, anchored, cli, guarded, limits, positive, walk
TOOL='hardlink-size-audit'

@guarded(TOOL)
def audit(root, *, max_entries=100000,max_depth=64,max_logical_bytes=None,max_allocated_bytes=None,
          require_contained_links=False,list_groups=False,max_findings=1000):
    limits(max_entries=max_entries,max_depth=max_depth,max_findings=max_findings)
    if max_logical_bytes is not None:limits(max_logical_bytes=max_logical_bytes)
    if max_allocated_bytes is not None:limits(max_allocated_bytes=max_allocated_bytes)
    report=Report(TOOL,max_findings);inodes={};logical=0;files=0;excluded=0
    with anchored(root,True) as fd:
        for rel,st,parent,name in walk(fd,max_entries,max_depth):
            if not stat.S_ISREG(st.st_mode):excluded+=1;continue
            files+=1;logical+=st.st_size
            if st.st_ino<=0:raise InputError('filesystem does not expose usable inode identities')
            key=(st.st_dev,st.st_ino);blocks=getattr(st,'st_blocks',None)
            if key not in inodes:inodes[key]={'bytes':st.st_size,'blocks':blocks,'nlink':st.st_nlink,'paths':[]}
            group=inodes[key]
            if (group['bytes'],group['blocks'],group['nlink'])!=(st.st_size,blocks,st.st_nlink):raise InputError('inode metadata changed during scan')
            group['paths'].append(rel)
    unique=sum(g['bytes'] for g in inodes.values())
    allocated=sum(g['blocks']*512 for g in inodes.values()) if all(g['blocks'] is not None for g in inodes.values()) else None
    groups=sorted((g for g in inodes.values() if len(g['paths'])>1),key=lambda g:g['paths'][0])
    uncontained=sum(1 for g in inodes.values() if g['nlink']>len(g['paths']))
    if require_contained_links:
        for group in sorted(inodes.values(),key=lambda g:g['paths'][0]):
            if group['nlink']>len(group['paths']):report.add('unaccounted_hardlinks',path=group['paths'][0],observed=len(group['paths']),reported_links=group['nlink'])
    if max_logical_bytes is not None and logical>max_logical_bytes:report.add('logical_byte_budget_exceeded',bytes=logical)
    if max_allocated_bytes is not None:
        if allocated is None:raise InputError('allocated-block accounting unavailable on this filesystem')
        if allocated>max_allocated_bytes:report.add('allocated_byte_budget_exceeded',bytes=allocated)
    summary={'regular_file_entries':files,'unique_regular_inodes':len(inodes),'logical_bytes':logical,'inode_unique_bytes':unique,
             'hardlink_duplicate_logical_bytes':logical-unique,'reported_allocated_bytes':allocated,
             'hardlink_groups':len(groups),'inodes_with_unaccounted_links':uncontained,'non_regular_entries_excluded':excluded}
    extra={}
    if list_groups:
        extra['groups']=[{'bytes_per_entry':g['bytes'],'entries':len(g['paths']),'paths':sorted(g['paths'])[:20],'paths_truncated':len(g['paths'])>20} for g in groups[:max_findings]]
        extra['groups_truncated']=len(groups)>max_findings
    return report.finish(summary,**extra)

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument('root')
    for name,default in [('max-entries',100000),('max-depth',64),('max-findings',1000)]:p.add_argument('--'+name,type=positive,default=default)
    p.add_argument('--max-logical-bytes',type=positive);p.add_argument('--max-allocated-bytes',type=positive)
    p.add_argument('--require-contained-links',action='store_true');p.add_argument('--list-groups',action='store_true')
    a=vars(p.parse_args());root=a.pop('root');return audit(root,**a)
if __name__=='__main__':raise SystemExit(cli(TOOL,parse_and_audit))

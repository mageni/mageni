#
#VID 0dccaa28-7f3c-11dd-8de5-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 0dccaa28-7f3c-11dd-8de5-0030843d3802
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "The following packages are affected:
   python24
   python25
   python23

CVE-2008-2315
Multiple integer overflows in Python 2.5.2 and earlier allow
context-dependent attackers to have an unknown impact via vectors
related to the (1) stringobject, (2) unicodeobject, (3) bufferobject,
(4) longobject, (5) tupleobject, (6) stropmodule, (7) gcmodule, and
(8) mmapmodule modules.
CVE-2008-2316
Integer overflow in _hashopenssl.c in the hashlib module in Python
2.5.2 and earlier might allow context-dependent attackers to defeat
cryptographic digests, related to 'partial hashlib hashing of data
exceeding 4GB.'
CVE-2008-3142
Multiple buffer overflows in Python 2.5.2 and earlier on 32bit
platforms allow context-dependent attackers to cause a denial of
service (crash) or have unspecified other impact via a long string
that leads to incorrect memory allocation during Unicode string
processing, related to the unicode_resize function and the
PyMem_RESIZE macro.
CVE-2008-3144
Multiple integer overflows in the PyOS_vsnprintf function in
Python/mysnprintf.c in Python 2.5.2 and earlier allow
context-dependent attackers to cause a denial of service (memory
corruption) or have unspecified other impact via crafted input to
string formatting operations.  NOTE: the handling of certain integer
values is also affected by related integer underflows and an
off-by-one error.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://bugs.python.org/issue2620
http://bugs.python.org/issue2588
http://bugs.python.org/issue2589
http://secunia.com/advisories/31305
http://mail.python.org/pipermail/python-checkins/2008-July/072276.html
http://mail.python.org/pipermail/python-checkins/2008-July/072174.html
http://mail.python.org/pipermail/python-checkins/2008-June/070481.html
http://www.vuxml.org/freebsd/0dccaa28-7f3c-11dd-8de5-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300310");
 script_version("$Revision: 4164 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-28 09:03:16 +0200 (Wed, 28 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-17 04:23:15 +0200 (Wed, 17 Sep 2008)");
 script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3144");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: python24");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"python24");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.5_2")<0) {
    txt += 'Package python24 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"python25");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.2_3")<0) {
    txt += 'Package python25 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"python23");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

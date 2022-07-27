#
#VID 4fb43b2f-46a9-11dd-9d38-00163e000016
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
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
tag_insight = "The following package is affected: freetype2

CVE-2008-1806
Integer overflow in FreeType2 before 2.3.6 allows context-dependent
attackers to execute arbitrary code via a crafted set of 16-bit length
values within the Private dictionary table in a Printer Font Binary
(PFB) file, which triggers a heap-based buffer overflow.

CVE-2008-1807
FreeType2 before 2.3.6 allow context-dependent attackers to execute
arbitrary code via an invalid 'number of axes' field in a Printer Font
Binary (PFB) file, which triggers a free of arbitrary memory
locations, leading to memory corruption.

CVE-2008-1808
Multiple off-by-one errors in FreeType2 before 2.3.6 allow
context-dependent attackers to execute arbitrary code via (1) a
crafted table in a Printer Font Binary (PFB) file or (2) a crafted SHC
instruction in a TrueType Font (TTF) file, which triggers a heap-based
buffer overflow.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/30600
http://sourceforge.net/project/shownotes.php?release_id=605780
http://www.vuxml.org/freebsd/4fb43b2f-46a9-11dd-9d38-00163e000016.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301140");
 script_version("$Revision: 4112 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-19 15:17:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
 script_bugtraq_id(29637,29639,29640,29641);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: freetype2");



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
bver = portver(pkg:"freetype2");
if(!isnull(bver) && revcomp(a:bver, b:"2.3.6")<0) {
    txt += 'Package freetype2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

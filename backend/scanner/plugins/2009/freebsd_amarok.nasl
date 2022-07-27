#
#VID 6bb6188c-17b2-11de-ae4d-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 6bb6188c-17b2-11de-ae4d-0030843d3802
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: amarok

CVE-2009-0135
Multiple integer overflows in the Audible::Tag::readTag function in
metadata/audible/audibletag.cpp in Amarok 1.4.10 through 2.0.1 allow
remote attackers to execute arbitrary code via an Audible Audio (.aa)
file with a large (1) nlen or (2) vlen Tag value, each of which
triggers a heap-based buffer overflow.

CVE-2009-0136
Multiple array index errors in the Audible::Tag::readTag function in
metadata/audible/audibletag.cpp in Amarok 1.4.10 through 2.0.1 allow
remote attackers to cause a denial of service (application crash) or
execute arbitrary code via an Audible Audio (.aa) file with a crafted
(1) nlen or (2) vlen Tag value, each of which can lead to an invalid
pointer dereference, or the writing of a 0x00 byte to an arbitrary
memory location, after an allocation failure.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.debian.org/security/2009/dsa-1706
http://secunia.com/advisories/33505
http://www.vuxml.org/freebsd/6bb6188c-17b2-11de-ae4d-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304488");
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2009-0135", "CVE-2009-0136");
 script_bugtraq_id(33210);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: amarok");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"amarok");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.10_3")<0) {
    txt += 'Package amarok version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

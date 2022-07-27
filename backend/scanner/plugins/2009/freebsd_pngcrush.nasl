#
#VID ea2411a4-08e8-11de-b88a-0022157515b2
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ea2411a4-08e8-11de-b88a-0022157515b2
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
tag_insight = "The following package is affected: pngcrush

CVE-2009-0040
The PNG reference library (aka libpng) before 1.0.43, and 1.2.x before
1.2.35, as used in pngcrush and other applications, allows
context-dependent attackers to cause a denial of service (application
crash) or possibly execute arbitrary code via a crafted PNG file that
triggers a free of an uninitialized pointer in (1) the png_read_png
function, (2) pCAL chunk handling, or (3) setup of 16-bit gamma
tables.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/33976
http://xforce.iss.net/xforce/xfdb/48819
http://www.vuxml.org/freebsd/ea2411a4-08e8-11de-b88a-0022157515b2.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311972");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2009-0040");
 script_bugtraq_id(33827);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: pngcrush");



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
bver = portver(pkg:"pngcrush");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.14")<0) {
    txt += 'Package pngcrush version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

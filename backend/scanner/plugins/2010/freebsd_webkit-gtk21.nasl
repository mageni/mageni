#
#VID e5090d2a-dbbe-11df-82f8-0015f2db7bde
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e5090d2a-dbbe-11df-82f8-0015f2db7bde
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: webkit-gtk2

CVE-2010-1780
Use-after-free vulnerability in WebKit in Apple Safari before 5.0.1 on
Mac OS X 10.5 through 10.6 and Windows, and before 4.1.1 on Mac OS X
10.4, allows remote attackers to execute arbitrary code or cause a
denial of service (application crash) via vectors related to element
focus.

CVE-2010-1807
WebKit in Apple Safari 4.x before 4.1.2 and 5.x before 5.0.2, and
Android before 2.2, does not properly validate floating-point data,
which allows remote attackers to execute arbitrary code or cause a
denial of service (application crash) via a crafted HTML document.

CVE-2010-1812
Use-after-free vulnerability in WebKit in Apple iOS before 4.1 on the
iPhone and iPod touch allows remote attackers to execute arbitrary
code or cause a denial of service (application crash) via vectors
involving selections.

CVE-2010-1814
WebKit in Apple iOS before 4.1 on the iPhone and iPod touch allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption and application crash) via vectors
involving form menus.

CVE-2010-1815
Use-after-free vulnerability in WebKit in Apple iOS before 4.1 on the
iPhone and iPod touch allows remote attackers to execute arbitrary
code or cause a denial of service (application crash) via vectors
involving scrollbars.

CVE-2010-3113
Google Chrome before 5.0.375.127 does not properly handle SVG
documents, which allows remote attackers to cause a denial of service
(memory corruption) or possibly have unspecified other impact via
unknown vectors.

CVE-2010-3114
The text-editing implementation in Google Chrome before 5.0.375.127
does not properly perform casts, which has unspecified impact and
attack vectors.

CVE-2010-3115
Google Chrome before 5.0.375.127 does not properly implement the
history feature, which might allow remote attackers to spoof the
address bar via unspecified vectors.

CVE-2010-3116
Google Chrome before 5.0.375.127 does not properly process MIME types,
which allows remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via unknown
vectors.

CVE-2010-3257
Google Chrome before 6.0.472.53 does not properly perform focus
handling, which allows remote attackers to cause a denial of service
or possibly have unspecified other impact via unknown vectors, related
to a 'stale pointer' issue.

CVE-2010-3259
Google Chrome before 6.0.472.53 does not properly restrict read access
to images, which allows remote attackers to bypass the Same Origin
Policy and obtain potentially sensitive information via unspecified
vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://gitorious.org/webkitgtk/stable/blobs/master/WebKit/gtk/NEWS
http://www.vuxml.org/freebsd/e5090d2a-dbbe-11df-82f8-0015f2db7bde.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313235");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-11-17 03:33:48 +0100 (Wed, 17 Nov 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1780", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-3113", "CVE-2010-3114", "CVE-2010-3115", "CVE-2010-3116", "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259");
 script_name("FreeBSD Ports: webkit-gtk2");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"webkit-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.5")<0) {
    txt += 'Package webkit-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

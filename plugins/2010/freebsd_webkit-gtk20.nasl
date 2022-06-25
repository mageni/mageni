#
#VID 9bcfd7b6-bcda-11df-9a6a-0015f2db7bde
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 9bcfd7b6-bcda-11df-9a6a-0015f2db7bde
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

CVE-2010-1782
WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.1 on Mac OS X 10.4, allows remote attackers to execute arbitrary code or cause a denial
of service.

CVE-2010-1784
The counters functionality in the CSS implementation in WebKit in Apple Safari before 5.0.1
on Mac OS X 10.5 through 10.6 and Windows, and before 4.1.1 on Mac OS X 10.4, allows remote
attackers to execute arbitrary code or cause a denial of service.

CVE-2010-1785
WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.1 on Mac OS X 10.4, accesses uninitialized memory during processing of the (1)
:first-letter and (2) :first-line pseudo-elements in an SVG text element, which allows remote
attackers to execute arbitrary code or cause a denial of service.

CVE-2010-1786
Use-after-free vulnerability in WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through
10.6 and Windows, and before 4.1.1 on Mac OS X 10.4, allows remote attackers to execute
arbitrary code or cause a denial of service via a foreignObject element in an SVG document.

CVE-2010-1787
WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.1 on Mac OS X 10.4, allows remote attackers to execute arbitrary code or cause a denial
of service.

CVE-2010-1788
WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.1 on Mac OS X 10.4, allows remote attackers to execute arbitrary code or cause a denial
of service.

CVE-2010-1790
WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.1 on Mac OS X 10.4, does not properly handle just-in-time (JIT) compiled JavaScript
stubs, which allows remote attackers to execute arbitrary code or cause a denial of service
via a crafted HTML document, related to a 'reentrancy issue.'

CVE-2010-1792
WebKit in Apple Safari before 5.0.1 on Mac OS X 10.5 through 10.6 and Windows, and before
4.1.1 on Mac OS X 10.4, allows remote attackers to execute arbitrary code or cause a denial
of service.

CVE-2010-1793
Multiple use-after-free vulnerabilities in WebKit in Apple Safari before 5.0.1 on Mac OS X
10.5 through 10.6 and Windows, and before 4.1.1 on Mac OS X 10.4, allow remote attackers to
execute arbitrary code or cause a denial of service via a (1) font-face or (2) use element
in an SVG document.

CVE-2010-2648
The implementation of the Unicode Bidirectional Algorithm in Google Chrome before 5.0.375.99
allows remote attackers to cause a denial of service or possibly have unspecified other impact
via unknown vectors.";
tag_solution = "Update your system with the appropriate patches or software upgrades.

http://gitorious.org/webkitgtk/stable/commit/9d07fda89aab7105962d933eef32ca15dda610d8
http://www.vuxml.org/freebsd/9bcfd7b6-bcda-11df-9a6a-0015f2db7bde.html";
tag_summary = "The remote host is missing an update to the system as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313290");
 script_version("$Revision: 8250 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1781", "CVE-2010-1782", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1790", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-2647", "CVE-2010-2648", "CVE-2010-3119");
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
if(!isnull(bver) && revcomp(a:bver, b:"1.2.4")<0) {
    txt += 'Package webkit-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

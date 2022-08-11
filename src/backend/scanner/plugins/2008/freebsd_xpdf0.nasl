#
#VID e3e266e9-5473-11d9-a9e7-0001020eed82
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
tag_insight = "The following packages are affected:
   xpdf
   kdegraphics
   gpdf
   teTeX-base
   cups-base
   koffice
   pdftohtml

CVE-2004-1125
Buffer overflow in the Gfx::doImage function in Gfx.cc for xpdf 3.00,
and other products that share code such as tetex-bin and kpdf in KDE
3.2.x to 3.2.3 and 3.3.x to 3.3.2, allows remote attackers to cause a
denial of service (application crash) and possibly execute arbitrary
code via a crafted PDF file that causes the boundaries of a maskColors
array to be exceeded.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.idefense.com/application/poi/display?id=172&type=vulnerabilities
http://www.vuxml.org/freebsd/e3e266e9-5473-11d9-a9e7-0001020eed82.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300112");
 script_version("$Revision: 4218 $");
 script_tag(name:"last_modification", value:"$Date: 2016-10-05 16:20:48 +0200 (Wed, 05 Oct 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1125");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: xpdf");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.00_5")<0) {
    txt += 'Package xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdegraphics");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.2_1")<0) {
    txt += 'Package kdegraphics version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"gpdf");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.1")<=0) {
    txt += 'Package gpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"teTeX-base");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.2_6")<=0) {
    txt += 'Package teTeX-base version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.22.0")<=0) {
    txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"koffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.5,1")<=0) {
    txt += 'Package koffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pdftohtml");
if(!isnull(bver) && revcomp(a:bver, b:"0.36_1")<0) {
    txt += 'Package pdftohtml version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

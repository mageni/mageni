#
#VID ef253f8b-0727-11d9-b45d-000c41e2cdad
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
   agenda-snow-libs
   linux_base
   open-motif-devel
   mupad
   zh-cle_base
   libXpm
   XFree86-libraries
   xorg-libraries
   lesstif
   xpm
   linux-openmotif
   open-motif

CVE-2004-0687
Multiple stack-based buffer overflows in (1) xpmParseColors in
parse.c, (2) ParseAndPutPixels in create.c, and (3) ParsePixels in
parse.c for libXpm before 6.8.1 allow remote attackers to execute
arbitrary code via a malformed XPM image file.

CVE-2004-0688
Multiple integer overflows in (1) the xpmParseColors function in
parse.c, (2) XpmCreateImageFromXpmImage, (3) CreateXImage, (4)
ParsePixels, and (5) ParseAndPutPixels for libXpm before 6.8.1 may
allow remote attackers to execute arbitrary code via a malformed XPM
image file.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://freedesktop.org/pipermail/xorg/2004-September/003172.html
http://scary.beasts.org/security/CESA-2004-003.txt
http://www.vuxml.org/freebsd/ef253f8b-0727-11d9-b45d-000c41e2cdad.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301353");
 script_version("$Revision: 4075 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-15 15:13:05 +0200 (Thu, 15 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("xpm -- image decoding vulnerabilities");



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
bver = portver(pkg:"agenda-snow-libs");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package agenda-snow-libs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux_base");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package linux_base version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"open-motif-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package open-motif-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mupad");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mupad version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-cle_base");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package zh-cle_base version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"libXpm");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.1_1")<0) {
    txt += 'Package libXpm version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"XFree86-libraries");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.0_1")<0) {
    txt += 'Package XFree86-libraries version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xorg-libraries");
if(!isnull(bver) && revcomp(a:bver, b:"6.7.0_2")<0) {
    txt += 'Package xorg-libraries version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"lesstif");
if(!isnull(bver) && revcomp(a:bver, b:"0.93.96,2")<0) {
    txt += 'Package lesstif version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xpm");
if(!isnull(bver) && revcomp(a:bver, b:"3.4k_1")<0) {
    txt += 'Package xpm version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-openmotif");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.4")<0) {
    txt += 'Package linux-openmotif version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"open-motif");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.3_1")<0) {
    txt += 'Package open-motif version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

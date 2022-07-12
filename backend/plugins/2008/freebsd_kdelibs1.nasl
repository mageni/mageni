#
#VID 641859e8-eca1-11d8-b913-000c41e2cdad
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
   kdelibs
   kdebase
   linux-opera
   opera
   firefox
   linux-mozilla
   linux-mozilla-devel
   mozilla-gtk1
   mozilla
   netscape7

CVE-2004-0717
Opera 7.51 for Windows and 7.50 for Linux does not properly prevent a
frame in one domain from injecting content into a frame that belongs
to another domain, which facilitates web site spoofing and other
attacks, aka the frame injection vulnerability.

CVE-2004-0718
The (1) Mozilla 1.6, (2) Firebird 0.7, (3) Firefox 0.8, and (4)
Netscape 7.1 web browsers do not properly prevent a frame in one
domain from injecting content into a frame that belongs to another
domain, which facilitates web site spoofing and other attacks, aka the
frame injection vulnerability.

CVE-2004-0721
Konqueror 3.1.3, 3.2.2, and possibly other versions does not properly
prevent a frame in one domain from injecting content into a frame that
belongs to another domain, which facilitates web site spoofing and
other attacks, aka the frame injection vulnerability.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/11978/
http://bugzilla.mozilla.org/show_bug.cgi?id=246448
ftp://ftp.kde.org/pub/kde/security_patches/post-3.2.3-kdelibs-htmlframes.patch
ftp://ftp.kde.org/pub/kde/security_patches/post-3.2.3-kdebase-htmlframes.patch
http://www.vuxml.org/freebsd/641859e8-eca1-11d8-b913-000c41e2cdad.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303559");
 script_version("$Revision: 4125 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-21 07:39:51 +0200 (Wed, 21 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0717", "CVE-2004-0718", "CVE-2004-0721");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: kdelibs");



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
bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.3_3")<0) {
    txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdebase");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.3_1")<0) {
    txt += 'Package kdebase version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"7.50")>=0 && revcomp(a:bver, b:"7.52")<0) {
    txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"7.50")>=0 && revcomp(a:bver, b:"7.52")<0) {
    txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"0.9")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7")<0) {
    txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.7")<0) {
    txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"1.7")<0) {
    txt += 'Package mozilla-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7,2")<0) {
    txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"7.2")<0) {
    txt += 'Package netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

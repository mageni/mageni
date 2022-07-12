#
#VID f6b6beaa-4e0e-11df-83fb-0015587e2cc1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID f6b6beaa-4e0e-11df-83fb-0015587e2cc1
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
tag_insight = "The following packages are affected:
   movemail
   emacs
   xemacs
   xemacs-devel
   xemacs-mule
   zh-xemacs-mule
   ja-xemacs-mule-canna
   xemacs-devel-mule
   xemacs-devel-mule-xft

CVE-2010-0825
lib-src/movemail.c in movemail in emacs 22 and 23 allows local users
to read, modify, or delete arbitrary mailbox files via a symlink
attack, related to improper file-permission checks.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/39155
http://www.ubuntu.com/usn/USN-919-1
http://www.vupen.com/english/advisories/2010/0734
http://xforce.iss.net/xforce/xfdb/57457
https://bugs.launchpad.net/ubuntu/+bug/531569
http://www.vuxml.org/freebsd/f6b6beaa-4e0e-11df-83fb-0015587e2cc1.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314319");
 script_version("$Revision: 8274 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
 script_cve_id("CVE-2010-0825");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: movemail");



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
bver = portver(pkg:"movemail");
if(!isnull(bver) && revcomp(a:bver, b:"1.0")<=0) {
    txt += 'Package movemail version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"emacs");
if(!isnull(bver) && revcomp(a:bver, b:"21.3_14")<=0) {
    txt += 'Package emacs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"22.3_1,1")>=0 && revcomp(a:bver, b:"22.3_4,1")<=0) {
    txt += 'Package emacs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"23.1")>=0 && revcomp(a:bver, b:"23.1_5,1")<=0) {
    txt += 'Package emacs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xemacs");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.22_4")<=0) {
    txt += 'Package xemacs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xemacs-devel");
if(!isnull(bver) && revcomp(a:bver, b:"21.5.b28_8,1")<=0) {
    txt += 'Package xemacs-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xemacs-mule");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.21_6")<=0) {
    txt += 'Package xemacs-mule version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-xemacs-mule");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.21_6")<=0) {
    txt += 'Package zh-xemacs-mule version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-xemacs-mule-canna");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.21_6")<=0) {
    txt += 'Package ja-xemacs-mule-canna version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xemacs-devel-mule");
if(!isnull(bver) && revcomp(a:bver, b:"21.5.b28_10")<=0) {
    txt += 'Package xemacs-devel-mule version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xemacs-devel-mule-xft");
if(!isnull(bver) && revcomp(a:bver, b:"21.5.b28_10")<=0) {
    txt += 'Package xemacs-devel-mule-xft version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

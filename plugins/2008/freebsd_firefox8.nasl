#
#VID b0911985-6e2a-11d9-9557-000a95bc6fae
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
   firefox
   mozilla
   linux-mozilla
   linux-mozilla-devel
   de-linux-mozillafirebird
   el-linux-mozillafirebird
   ja-linux-mozillafirebird-gtk1
   ja-mozillafirebird-gtk2
   linux-mozillafirebird
   ru-linux-mozillafirebird
   zhCN-linux-mozillafirebird
   zhTW-linux-mozillafirebird
   de-netscape7
   fr-netscape7
   ja-netscape7
   netscape7
   pt_BR-netscape7
   mozilla-gtk1
   de-linux-netscape
   fr-linux-netscape
   ja-linux-netscape
   linux-netscape
   linux-phoenix
   mozilla+ipv6
   mozilla-embedded
   mozilla-firebird
   mozilla-gtk2
   mozilla-gtk
   mozilla-thunderbird
   phoenix
   kdebase
   kdelibs
   opera
   opera-devel
   linux-opera

CVE-2004-1156
Mozilla before 1.7.6, and Firefox before 1.0.1, allows remote
attackers to spoof arbitrary web sites by injecting content from one
window into a target window whose name is known but resides in a
different domain, as demonstrated using a pop-up window on a trusted
web site, aka the 'window injection' vulnerability.

CVE-2004-1157
Opera 7.x up to 7.54, and possibly other versions, allows remote
attackers to spoof arbitrary web sites by injecting content from one
window into a target window whose name is known but resides in a
different domain, as demonstrated using a pop-up window on a trusted
web site, aka the 'window injection' vulnerability.

CVE-2004-1158
Konqueror 3.x up to 3.2.2-6, and possibly other versions, allows
remote attackers to spoof arbitrary web sites by injecting content
from one window into a target window or tab whose name is known but
resides in a different domain, as demonstrated using a pop-up window
on a trusted web site, aka the 'window injection' vulnerability.

CVE-2004-1160
Netscape 7.x to 7.2, and possibly other versions, allows remote
attackers to spoof arbitrary web sites by injecting content from one
window into a target window whose name is known but resides in a
different domain, as demonstrated using a pop-up window on a trusted
web site, aka the 'window injection' vulnerability.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/secunia_research/2004-13/advisory/
http://secunia.com/multiple_browsers_window_injection_vulnerability_test/
http://secunia.com/advisories/13129/
https://bugzilla.mozilla.org/show_bug.cgi?id=273699
https://bugzilla.mozilla.org/show_bug.cgi?id=103638
http://mozillanews.org/?article_date=2004-12-08+06-48-46
http://secunia.com/advisories/13253/
http://secunia.com/advisories/13254/
http://www.kde.org/info/security/advisory-20041213-1.txt
http://secunia.com/advisories/13402/
http://www.vuxml.org/freebsd/b0911985-6e2a-11d9-9557-000a95bc6fae.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300757");
 script_version("$Revision: 4112 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-19 15:17:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1156", "CVE-2004-1157", "CVE-2004-1158", "CVE-2004-1160");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: firefox");



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
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.1,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.6,2")<0) {
    txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.6")<0) {
    txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.6")<0) {
    txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package de-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"el-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package el-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-linux-mozillafirebird-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ja-linux-mozillafirebird-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-mozillafirebird-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ja-mozillafirebird-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ru-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zhCN-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package zhCN-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zhTW-linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package zhTW-linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package de-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package fr-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ja-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt_BR-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package pt_BR-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package de-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package fr-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ja-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-phoenix");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package linux-phoenix version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-embedded");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-embedded version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-firebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-firebird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"phoenix");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package phoenix version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdebase");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.2")<0) {
    txt += 'Package kdebase version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.2")<0) {
    txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"7.54.20050131")<0) {
    txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"opera-devel");
if(!isnull(bver) && revcomp(a:bver, b:"7.54.20050131")<0) {
    txt += 'Package opera-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"7.54.20050131")<0) {
    txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

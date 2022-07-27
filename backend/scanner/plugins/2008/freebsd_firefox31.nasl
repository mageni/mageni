#
#VID 810a5197-e0d9-11dc-891a-02061b08fc24
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
   linux-firefox
   seamonkey
   linux-seamonkey
   flock
   linux-flock
   linux-firefox-devel
   linux-seamonkey-devel

For details, please visit the referenced security advisories.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/2008/mfsa2008-01.html
http://www.mozilla.org/security/announce/2008/mfsa2008-02.html
http://www.mozilla.org/security/announce/2008/mfsa2008-03.html
http://www.mozilla.org/security/announce/2008/mfsa2008-04.html
http://www.mozilla.org/security/announce/2008/mfsa2008-05.html
http://www.mozilla.org/security/announce/2008/mfsa2008-06.html
http://www.mozilla.org/security/announce/2008/mfsa2008-07.html
http://www.mozilla.org/security/announce/2008/mfsa2008-08.html
http://www.mozilla.org/security/announce/2008/mfsa2008-09.html
http://www.mozilla.org/security/announce/2008/mfsa2008-10.html
http://www.mozilla.org/security/announce/2008/mfsa2008-11.html
http://www.vuxml.org/freebsd/810a5197-e0d9-11dc-891a-02061b08fc24.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304199");
 script_version("$Revision: 4112 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-19 15:17:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: firefox");



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
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.0.12,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.0.12")<0) {
    txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.8")<0) {
    txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.8")<0) {
    txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"flock");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.9")<0) {
    txt += 'Package flock version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-flock");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.9")<0) {
    txt += 'Package linux-flock version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package linux-firefox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package linux-seamonkey-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

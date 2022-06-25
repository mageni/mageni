#
#VID d47e9d19-5016-11d9-9b5f-0050569f0001
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
   mod_php4-twig
   php4-cgi
   php4-cli
   php4-dtc
   php4-horde
   php4-nms
   php4
   mod_php
   mod_php4
   php5
   php5-cgi
   php5-cli
   mod_php5

CVE-2004-1019
The deserialization code in PHP before 4.3.10 and PHP 5.x up to 5.0.2
allows remote attackers to cause a denial of service and execute
arbitrary code via untrusted data to the unserialize function that may
trigger 'information disclosure, double free and negative reference
index array underflow' results.

CVE-2004-1065
Buffer overflow in the exif_read_data function in PHP before 4.3.10
and PHP 5.x up to 5.0.2 allows remote attackers to execute arbitrary
code via a long section name in an image file.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/13481/
http://www.php.net/release_4_3_10.php
http://www.hardened-php.net/advisories/012004.txt
http://www.vuxml.org/freebsd/d47e9d19-5016-11d9-9b5f-0050569f0001.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301080");
 script_version("$Revision: 4128 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-22 07:37:51 +0200 (Thu, 22 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-1019", "CVE-2004-1065");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("php -- multiple vulnerabilities");



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
bver = portver(pkg:"mod_php4-twig");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package mod_php4-twig version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package php4-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-cli");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package php4-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package php4-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-horde");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package php4-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-nms");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package php4-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.10")<0) {
    txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php");
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.3.10,1")<0) {
    txt += 'Package mod_php version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php4");
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.3.10,1")<0) {
    txt += 'Package mod_php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.3")<0) {
    txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.3")<0) {
    txt += 'Package php5-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-cli");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.3")<0) {
    txt += 'Package php5-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.3,1")<0) {
    txt += 'Package mod_php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

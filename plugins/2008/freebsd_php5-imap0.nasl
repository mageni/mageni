#
#VID f5e52bf5-fc77-11db-8163-000e0c2e438a
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
   php5-imap
   php5-odbc
   php5-session
   php5-shmop
   php5-sqlite
   php5-wddx
   php5
   php4-odbc
   php4-session
   php4-shmop
   php4-wddx
   php4
   mod_php4-twig
   mod_php4
   mod_php5
   mod_php
   php4-cgi
   php4-cli
   php4-dtc
   php4-horde
   php4-nms
   php5-cgi
   php5-cli
   php5-dtc
   php5-horde
   php5-nms

=====";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.php.net/releases/4_4_7.php
http://www.php.net/releases/5_2_2.php
http://www.vuxml.org/freebsd/f5e52bf5-fc77-11db-8163-000e0c2e438a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300169");
 script_version("$Revision: 4148 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-27 07:32:19 +0200 (Tue, 27 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2007-1001");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("php -- multiple vulnerabilities");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"php5-imap");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5-imap version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-odbc");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5-odbc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-session");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5-session version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-shmop");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5-shmop version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-sqlite");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5-sqlite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-wddx");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5-wddx version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.2")<0) {
    txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-odbc");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.7")<0) {
    txt += 'Package php4-odbc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-session");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.7")<0) {
    txt += 'Package php4-session version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-shmop");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.7")<0) {
    txt += 'Package php4-shmop version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-wddx");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.7")<0) {
    txt += 'Package php4-wddx version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.7")<0) {
    txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php4-twig");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mod_php4-twig version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php4");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mod_php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php5");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mod_php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mod_php");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mod_php version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php4-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-cli");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php4-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php4-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-horde");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php4-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php4-nms");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php4-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php5-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-cli");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php5-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php5-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-horde");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php5-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"php5-nms");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package php5-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

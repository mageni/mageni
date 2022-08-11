#
#VID ac619d06-3ef8-11d9-8741-c942c075aa41
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
   jdk
   linux-jdk
   linux-sun-jdk
   linux-blackdown-jdk
   linux-ibm-jdk
   diablo-jdk
   diablo-jre

CVE-2004-1029
The Sun Java Plugin capability in Java 2 Runtime Environment (JRE)
1.4.2_01, 1.4.2_04, and possibly earlier versions, does not properly
restrict access between Javascript and Java applets during data
transfer, which allows remote attackers to load unsafe classes and
execute arbitrary code.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://sunsolve.sun.com/search/document.do?assetkey=1-26-57591-1&searchclause=%22category:security%22%20%22availability,%20security%22
http://marc.theaimsgroup.com/?l=bugtraq&m=110125046627909
http://www.vuxml.org/freebsd/ac619d06-3ef8-11d9-8741-c942c075aa41.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300634");
 script_version("$Revision: 4125 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-21 07:39:51 +0200 (Wed, 21 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(11726);
 script_cve_id("CVE-2004-1029");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: jdk");



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
bver = portver(pkg:"jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.0")>=0 && revcomp(a:bver, b:"1.4.2p6_6")<=0) {
    txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.1p9_4")<=0) {
    txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.0")>=0 && revcomp(a:bver, b:"1.4.2.05")<=0) {
    txt += 'Package linux-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.1.13")<=0) {
    txt += 'Package linux-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-sun-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.0")>=0 && revcomp(a:bver, b:"1.4.2.05")<=0) {
    txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.1.13")<=0) {
    txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-blackdown-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.4.2")<=0) {
    txt += 'Package linux-blackdown-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-ibm-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.4.2")<=0) {
    txt += 'Package linux-ibm-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"diablo-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1.0")>=0 && revcomp(a:bver, b:"1.3.1.0_1")<=0) {
    txt += 'Package diablo-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"diablo-jre");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1.0")>=0 && revcomp(a:bver, b:"1.3.1.0_1")<=0) {
    txt += 'Package diablo-jre version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

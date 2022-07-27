#
#VID 18e5428f-ae7c-11d9-837d-000e0c2e438a
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
   linux-ibm-jdk
   linux-sun-jdk
   linux-blackdown-jdk
   diablo-jdk
   linux-jdk

CVE-2005-1080
Directory traversal vulnerability in the Java Archive Tool (Jar)
utility in J2SE SDK 1.4.2, 1.5 allows remote attackersto write
arbitrary files via a .. (dot dot) in filenames in a .jar file.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.securiteam.com/securitynews/5IP0C0AFGW.html
http://secunia.com/advisories/14902/
http://marc.theaimsgroup.com/?l=bugtraq&m=111331593310508
http://www.vuxml.org/freebsd/18e5428f-ae7c-11d9-837d-000e0c2e438a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301574");
 script_version("$Revision: 4125 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-21 07:39:51 +0200 (Wed, 21 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-1080");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
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
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2p8")<=0) {
    txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.5")>=0 && revcomp(a:bver, b:"1.5.0p1_1")<=0) {
    txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-ibm-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2_1")<=0) {
    txt += 'Package linux-ibm-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-sun-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2.08_1")<=0) {
    txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.5")>=0 && revcomp(a:bver, b:"1.5.2.02,2")<=0) {
    txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-blackdown-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2_2")<=0) {
    txt += 'Package linux-blackdown-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"diablo-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1.0_1")<=0) {
    txt += 'Package diablo-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package linux-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

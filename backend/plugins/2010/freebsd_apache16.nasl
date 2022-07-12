#
#VID cae01d7b-110d-11df-955a-00219b0fc4d8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID cae01d7b-110d-11df-955a-00219b0fc4d8
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
   apache
   apache+mod_perl
   apache+ipv6
   apache_fp
   ru-apache
   ru-apache+mod_ssl
   apache+ssl
   apache+mod_ssl
   apache+mod_ssl+ipv6
   apache+mod_ssl+mod_accel
   apache+mod_ssl+mod_accel+ipv6
   apache+mod_ssl+mod_accel+mod_deflate
   apache+mod_ssl+mod_accel+mod_deflate+ipv6
   apache+mod_ssl+mod_deflate
   apache+mod_ssl+mod_deflate+ipv6
   apache+mod_ssl+mod_snmp
   apache+mod_ssl+mod_snmp+mod_accel
   apache+mod_ssl+mod_snmp+mod_accel+ipv6
   apache+mod_ssl+mod_snmp+mod_deflate
   apache+mod_ssl+mod_snmp+mod_deflate+ipv6
   apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";

tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314727");
 script_version("$Revision: 8485 $");
 script_cve_id("CVE-2010-0010");
 script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: apache");

 script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-0010");
 script_xref(name:"URL", value:"http://www.vupen.com/english/Reference-CVE-2010-0010.php");
 script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/cae01d7b-110d-11df-955a-00219b0fc4d8.html");

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
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_perl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42")<0) {
    txt += 'Package apache+mod_perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42")<0) {
    txt += 'Package apache+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache_fp");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package apache_fp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+30.23")<0) {
    txt += 'Package ru-apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42")<0) {
    txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42.1.57_2")<0) {
    txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.42+2.8.27_1")<0) {
    txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

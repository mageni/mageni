#
#VID ca9ce879-5ebb-11d9-a01c-0050569f0001
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
   exim
   exim-ldap
   exim-ldap2
   exim-mysql
   exim-postgresql
   exim-sa-exim

CVE-2005-0021
Multiple buffer overflows in Exim before 4.43 may allow attackers to
execute arbitrary code via (1) an IPv6 address with more than 8
components, as demonstrated using the -be command line option, which
triggers an overflow in the host_aton function, or (2) the -bh command
line option or dnsdb PTR lookup, which triggers an overflow in the
dns_build_reverse function.

CVE-2005-0022
Buffer overflow in the spa_base64_to_bits function in Exim before
4.43, as originally obtained from Samba code, and as called by the
auth_spa_client function, may allow attackers to execute arbitrary
code during SPA authentication.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.exim.org/mail-archives/exim-announce/2005/msg00000.html
http://marc.theaimsgroup.com/?l=bugtraq&m=110573573800377
http://www.vuxml.org/freebsd/ca9ce879-5ebb-11d9-a01c-0050569f0001.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303231");
 script_version("$Revision: 4078 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-16 07:34:17 +0200 (Fri, 16 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-0021", "CVE-2005-0022");
 script_bugtraq_id(12185,12188,12268);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("exim -- two buffer overflow vulnerabilities");



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
bver = portver(pkg:"exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
    txt += 'Package exim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-ldap");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
    txt += 'Package exim-ldap version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-ldap2");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
    txt += 'Package exim-ldap2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-mysql");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
    txt += 'Package exim-mysql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
    txt += 'Package exim-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"exim-sa-exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
    txt += 'Package exim-sa-exim version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

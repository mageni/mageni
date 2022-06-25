#
#VID 1583640d-be20-11dd-a578-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1583640d-be20-11dd-a578-0030843d3802
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
   samba
   samba3
   ja-samba
   samba32-devel

CVE-2008-4314
smbd in Samba 3.0.29 through 3.2.4 might allow remote attackers to
read arbitrary memory and cause a denial of service via crafted (1)
trans, (2) trans2, and (3) nttrans requests, related to a 'cut&paste
error' that causes an improper bounds check to be performed.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.samba.org/samba/security/CVE-2008-4314.html
http://secunia.com/advisories/32813/
http://www.vuxml.org/freebsd/1583640d-be20-11dd-a578-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301258");
 script_version("$Revision: 4175 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-29 07:45:50 +0200 (Thu, 29 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
 script_cve_id("CVE-2008-4314");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
 script_name("FreeBSD Ports: samba, samba3, ja-samba");



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
bver = portver(pkg:"samba");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.29,1")>=0 && revcomp(a:bver, b:"3.0.32_2,1")<0) {
    txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"samba3");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.29,1")>=0 && revcomp(a:bver, b:"3.0.32_2,1")<0) {
    txt += 'Package samba3 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-samba");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.29,1")>=0 && revcomp(a:bver, b:"3.0.32_2,1")<0) {
    txt += 'Package ja-samba version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"samba32-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.4_1")<0) {
    txt += 'Package samba32-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

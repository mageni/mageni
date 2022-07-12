#
#VID 6a5174bd-c580-11da-9110-00123ffe8333
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
   clamav
   clamav-devel

CVE-2006-1614
Integer overflow in the cli_scanpe function in the PE header parser
(libclamav/pe.c) in Clam AntiVirus (ClamAV) before 0.88.1, when
ArchiveMaxFileSize is disabled, allows remote attackers to cause a
denial of service and possibly execute arbitrary code.

CVE-2006-1615
Multiple format string vulnerabilities in the logging code in Clam
AntiVirus (ClamAV) before 0.88.1 might allow remote attackers to
execute arbitrary code.  NOTE: as of 20060410, it is unclear whether
this is a vulnerability, as there is some evidence that the arguments
are actually being sanitized properly.

CVE-2006-1630
The cli_bitset_set function in libclamav/others.c in Clam AntiVirus
(ClamAV) before 0.88.1 allows remote attackers to cause a denial of
service via unspecified vectors that trigger an 'invalid memory
access.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/19534/
http://www.us.debian.org/security/2006/dsa-1024
http://www.vuxml.org/freebsd/6a5174bd-c580-11da-9110-00123ffe8333.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300981");
 script_version("$Revision: 4075 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-15 15:13:05 +0200 (Thu, 15 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-1614", "CVE-2006-1615", "CVE-2006-1630");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: clamav");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"clamav");
if(!isnull(bver) && revcomp(a:bver, b:"0.88.1")<0) {
    txt += 'Package clamav version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"clamav-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20051104_1")<=0) {
    txt += 'Package clamav-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

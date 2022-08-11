#
#VID 249a8c42-6973-11d9-ae49-000c41e2cdad
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
   zgv
   xzgv

CVE-2004-0994
Multiple integer overflows in xzgv 0.8 and earlier allow remote
attackers to execute arbitrary code via images with large width and
height values, which trigger a heap-based buffer overflow, as
demonstrated in the read_prf_file function in readprf.c.  NOTE:
CVE-2004-0994 and CVE-2004-1095 identify sets of bugs that only
partially overlap, despite having the same developer.  Therefore, they
should be regarded as distinct.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://rus.members.beeb.net/xzgv.html
http://www.svgalib.org/rus/zgv/
http://www.idefense.com/application/poi/display?id=160&type=vulnerabilities&flashstatus=false
http://marc.theaimsgroup.com/?l=bugtraq&m=109886210702781
http://marc.theaimsgroup.com/?l=bugtraq&m=109898111915661
http://www.vuxml.org/freebsd/249a8c42-6973-11d9-ae49-000c41e2cdad.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303870");
 script_version("$Revision: 4218 $");
 script_tag(name:"last_modification", value:"$Date: 2016-10-05 16:20:48 +0200 (Wed, 05 Oct 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0994");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: zgv");



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
bver = portver(pkg:"zgv");
if(!isnull(bver) && revcomp(a:bver, b:"5.8_1")<0) {
    txt += 'Package zgv version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"xzgv");
if(!isnull(bver) && revcomp(a:bver, b:"0.8_2")<0) {
    txt += 'Package xzgv version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

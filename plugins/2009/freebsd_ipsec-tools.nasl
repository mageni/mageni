#
#VID abcacb5a-e7f1-11dd-afcd-00e0815b8da8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID abcacb5a-e7f1-11dd-afcd-00e0815b8da8
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: ipsec-tools

CVE-2008-3651
Memory leak in racoon/proposal.c in the racoon daemon in ipsec-tools
before 0.7.1 allows remote authenticated users to cause a denial of
service (memory consumption) via invalid proposals.

CVE-2008-3652
src/racoon/handler.c in racoon in ipsec-tools does not remove an
'orphaned ph1' (phase 1) handle when it has been initiated remotely,
which allows remote attackers to cause a denial of service (resource
consumption).";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://marc.info/?l=ipsec-tools-devel&m=121688914101709&w=2
http://www.vuxml.org/freebsd/abcacb5a-e7f1-11dd-afcd-00e0815b8da8.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310266");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
 script_cve_id("CVE-2008-3651", "CVE-2008-3652");
 script_bugtraq_id(30657);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("FreeBSD Ports: ipsec-tools");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"ipsec-tools");
if(!isnull(bver) && revcomp(a:bver, b:"0.7.1")<0) {
    txt += 'Package ipsec-tools version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

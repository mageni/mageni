#
#VID 24ec781b-8c11-11dd-9923-0016d325a0ed
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 24ec781b-8c11-11dd-9923-0016d325a0ed
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
tag_insight = "The following package is affected: bitlbee

CVE-2008-3920
Unspecified vulnerability in BitlBee before 1.2.2 allows remote
attackers to 'recreate' and 'hijack' existing accounts via unspecified
vectors.
CVE-2008-3969
Multiple unspecified vulnerabilities in BitlBee before 1.2.3 allow
remote attackers to 'overwrite' and 'hijack' existing accounts via
unknown vectors.  NOTE: this issue exists because of an incomplete fix
for CVE-2008-3920.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/31633/
http://www.vuxml.org/freebsd/24ec781b-8c11-11dd-9923-0016d325a0ed.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303476");
 script_version("$Revision: 4075 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-15 15:13:05 +0200 (Thu, 15 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-10-03 23:16:57 +0200 (Fri, 03 Oct 2008)");
 script_cve_id("CVE-2008-3920", "CVE-2008-3969");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: bitlbee");



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
bver = portver(pkg:"bitlbee");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.3")<0) {
    txt += 'Package bitlbee version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

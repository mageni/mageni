#
#VID f762ccbb-baed-11dc-a302-000102cc8983
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
tag_insight = "The following package is affected: linux-realplayer

CVE-2007-5081
Heap-based buffer overflow in RealNetworks RealPlayer 8, 10, 10.1, and
possibly 10.5; RealOne Player 1 and 2; and RealPlayer Enterprise
allows remote attackers to execute arbitrary code via a crafted RM
file.
CVE-2007-3410
Stack-based buffer overflow in the SmilTimeValue::parseWallClockValue
function in smlprstime.cpp in RealNetworks RealPlayer 10, 10.1, and
possibly 10.5, RealOne Player, RealPlayer Enterprise, and Helix Player
10.5-GOLD and 10.0.5 through 10.0.8, allows remote attackers to
execute arbitrary code via an SMIL (SMIL2) file with a long wallclock
value.
CVE-2007-2263
Heap-based buffer overflow in RealNetworks RealPlayer 10.0, 10.1, and
possibly 10.5, RealOne Player, and RealPlayer Enterprise allows remote
attackers to execute arbitrary code via an SWF (Flash) file with
malformed record headers.
CVE-2007-2264
Heap-based buffer overflow in RealNetworks RealPlayer 8, 10, 10.1, and
possibly 10.5; RealOne Player 1 and 2; and RealPlayer Enterprise
allows remote attackers to execute arbitrary code via a RAM (.ra or
.ram) file with a large size value in the RA header.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/27361
http://service.real.com/realplayer/security/10252007_player/en/
http://www.zerodayinitiative.com/advisories/ZDI-07-063.html
http://www.zerodayinitiative.com/advisories/ZDI-07-062.html
http://www.zerodayinitiative.com/advisories/ZDI-07-061.html
http://secunia.com/advisories/25819/
http://www.vuxml.org/freebsd/f762ccbb-baed-11dc-a302-000102cc8983.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301887");
 script_version("$Revision: 4128 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-22 07:37:51 +0200 (Thu, 22 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2007-5081", "CVE-2007-3410", "CVE-2007-2263", "CVE-2007-2264");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: linux-realplayer");



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
bver = portver(pkg:"linux-realplayer");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5")>=0 && revcomp(a:bver, b:"10.0.9.809.20070726")<0) {
    txt += 'Package linux-realplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

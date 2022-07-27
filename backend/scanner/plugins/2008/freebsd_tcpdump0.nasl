#
#VID 96ba2dae-4ab0-11d8-96f2-0020ed76ef5a
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
tag_insight = "The following package is affected: tcpdump

CVE-2003-0989
tcpdump before 3.8.1 allows remote attackers to cause a denial of
service (infinite loop) via certain ISAKMP packets, a different
vulnerability than CVE-2004-0057.

CVE-2003-1029
The L2TP protocol parser in tcpdump 3.8.1 and earlier allows remote
attackers to cause a denial of service (infinite loop and memory
consumption) via a packet with invalid data to UDP port 1701, which
causes l2tp_avp_print to use a bad length value when calling
print_octets.

CVE-2004-0057
The rawprint function in the ISAKMP decoding routines (print-isakmp.c)
for tcpdump 3.8.1 and earlier allows remote attackers to cause a
denial of service (segmentation fault) via malformed ISAKMP packets
that cause invalid 'len' or 'loc' values to be used in a loop, a
different vulnerability than CVE-2003-0989.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.tcpdump.org/lists/workers/2003/12/msg00083.html
http://marc.theaimsgroup.com/?l=tcpdump-workers&m=107325073018070&w=2
http://www.vuxml.org/freebsd/96ba2dae-4ab0-11d8-96f2-0020ed76ef5a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301690");
 script_version("$Revision: 4188 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-30 07:56:47 +0200 (Fri, 30 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0057");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: tcpdump");



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
bver = portver(pkg:"tcpdump");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.1_351")<0) {
    txt += 'Package tcpdump version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

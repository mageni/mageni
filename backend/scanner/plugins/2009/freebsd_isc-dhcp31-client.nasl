#
#VID c444c8b7-7169-11de-9ab7-000c29a67389
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID c444c8b7-7169-11de-9ab7-000c29a67389
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
tag_insight = "The following packages are affected:
   isc-dhcp31-client
   isc-dhcp30-client

CVE-2009-0692
Stack-based buffer overflow in the script_write_params method in
client/dhclient.c in ISC DHCP dhclient 4.1 before 4.1.0p1, 4.0 before
4.0.1p1, 3.1 before 3.1.2p1, 3.0, and 2.0 allows remote DHCP servers
to execute arbitrary code via a crafted subnet-mask option.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://www.isc.org/node/468
http://secunia.com/advisories/35785
http://www.kb.cert.org/vuls/id/410676
http://www.vuxml.org/freebsd/c444c8b7-7169-11de-9ab7-000c29a67389.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306627");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-0692");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: isc-dhcp31-client");



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
bver = portver(pkg:"isc-dhcp31-client");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.1")<=0) {
    txt += 'Package isc-dhcp31-client version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"isc-dhcp30-client");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.7")<=0) {
    txt += 'Package isc-dhcp30-client version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

# OpenVAS Vulnerability Test
# $Id: mdksa_2009_312.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:312 (dhcp)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "A vulnerability has been found and corrected in ISC DHCP:

Integer overflow in the ISC dhcpd 3.0.x before 3.0.7 and 3.1.x before
3.1.1; and the DHCP server in EMC VMware Workstation before 5.5.5 Build
56455 and 6.x before 6.0.1 Build 55017, Player before 1.0.5 Build 56455
and Player 2 before 2.0.1 Build 55017, ACE before 1.0.3 Build 54075 and
ACE 2 before 2.0.1 Build 55017, and Server before 1.0.4 Build 56528;
allows remote attackers to cause a denial of service (daemon crash)
or execute arbitrary code via a malformed DHCP packet with a large
dhcp-max-message-size that triggers a stack-based buffer overflow,
related to servers configured to send many DHCP options to clients
(CVE-2007-0062).

Stack-based buffer overflow in the script_write_params method in
client/dhclient.c in ISC DHCP dhclient 4.1 before 4.1.0p1, 4.0
before 4.0.1p1, 3.1 before 3.1.2p1, 3.0, and 2.0 allows remote DHCP
servers to execute arbitrary code via a crafted subnet-mask option
(CVE-2009-0692).

ISC DHCP Server is vulnerable to a denial of service, caused by the
improper handling of DHCP requests. If the host definitions are mixed
using dhcp-client-identifier and hardware ethernet, a remote attacker
could send specially-crafted DHCP requests to cause the server to
stop responding (CVE-2009-1892).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update provides fixes for this vulnerability.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:312";
tag_summary = "The remote host is missing an update to dhcp
announced via advisory MDVSA-2009:312.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309995");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2007-0062", "CVE-2009-0692", "CVE-2009-1892");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:312 (dhcp)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms");
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

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~3.0.7~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

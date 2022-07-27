# OpenVAS Vulnerability Test
# $Id: mdksa_2009_056.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:056 (net-snmp)
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
tag_insight = "A vulnerability has been identified and corrected in net-snmp:

The netsnmp_udp_fmtaddr function (snmplib/snmpUDPDomain.c) in
net-snmp 5.0.9 through 5.4.2, when using TCP wrappers for client
authorization, does not properly parse hosts.allow rules, which
allows remote attackers to bypass intended access restrictions
and execute SNMP queries, related to source/destination IP address
confusion. (CVE-2008-6123)

The updated packages have been patched to prevent this.

Affected: 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:056";
tag_summary = "The remote host is missing an update to net-snmp
announced via advisory MDVSA-2009:056.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305611");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
 script_cve_id("CVE-2008-6123");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Mandrake Security Advisory MDVSA-2009:056 (net-snmp)");



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
if ((res = isrpmvuln(pkg:"libnet-snmp15", rpm:"libnet-snmp15~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp-devel", rpm:"libnet-snmp-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp-static-devel", rpm:"libnet-snmp-static-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-tkmib", rpm:"net-snmp-tkmib~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-NetSNMP", rpm:"perl-NetSNMP~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp15", rpm:"lib64net-snmp15~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp-devel", rpm:"lib64net-snmp-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp-static-devel", rpm:"lib64net-snmp-static-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

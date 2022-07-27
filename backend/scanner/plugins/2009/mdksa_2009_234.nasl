# OpenVAS Vulnerability Test
# $Id: mdksa_2009_234.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:234 (silc-toolkit)
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
tag_insight = "Multiple vulnerabilities was discovered and corrected in silc-toolkit:

Multiple format string vulnerabilities in lib/silcclient/client_entry.c
in Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10, and
SILC Client before 1.1.8, allow remote attackers to execute arbitrary
code via format string specifiers in a nickname field, related to the
(1) silc_client_add_client, (2) silc_client_update_client, and (3)
silc_client_nickname_format functions (CVE-2009-3051).

The silc_asn1_encoder function in lib/silcasn1/silcasn1_encode.c in
Secure Internet Live Conferencing (SILC) Toolkit before 1.1.8 allows
remote attackers to overwrite a stack location and possibly execute
arbitrary code via a crafted OID value, related to incorrect use of
a %lu format string (CVE-2008-7159).

The silc_http_server_parse function in lib/silchttp/silchttpserver.c in
the internal HTTP server in silcd in Secure Internet Live Conferencing
(SILC) Toolkit before 1.1.9 allows remote attackers to overwrite
a stack location and possibly execute arbitrary code via a crafted
Content-Length header, related to incorrect use of a %lu format string
(CVE-2008-7160).

Multiple format string vulnerabilities in lib/silcclient/command.c
in Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10,
and SILC Client 1.1.8 and earlier, allow remote attackers to execute
arbitrary code via format string specifiers in a channel name, related
to (1) silc_client_command_topic, (2) silc_client_command_kick,
(3) silc_client_command_leave, and (4) silc_client_command_users
(CVE-2009-3163).

This update provides a solution to these vulnerabilities.

Affected: 2008.1, 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:234";
tag_summary = "The remote host is missing an update to silc-toolkit
announced via advisory MDVSA-2009:234.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309194");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-21 23:13:00 +0200 (Mon, 21 Sep 2009)");
 script_cve_id("CVE-2009-3051", "CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3163");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:234 (silc-toolkit)");



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
if ((res = isrpmvuln(pkg:"libsilc1.1_2", rpm:"libsilc1.1_2~1.1.7~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilcclient1.1_2", rpm:"libsilcclient1.1_2~1.1.7~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit", rpm:"silc-toolkit~1.1.7~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit-devel", rpm:"silc-toolkit-devel~1.1.7~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64silc1.1_2", rpm:"lib64silc1.1_2~1.1.7~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64silcclient1.1_2", rpm:"lib64silcclient1.1_2~1.1.7~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilc1.1_2", rpm:"libsilc1.1_2~1.1.7~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilcclient1.1_2", rpm:"libsilcclient1.1_2~1.1.7~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit", rpm:"silc-toolkit~1.1.7~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit-devel", rpm:"silc-toolkit-devel~1.1.7~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64silc1.1_2", rpm:"lib64silc1.1_2~1.1.7~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64silcclient1.1_2", rpm:"lib64silcclient1.1_2~1.1.7~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

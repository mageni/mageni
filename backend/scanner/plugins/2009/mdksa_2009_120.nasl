# OpenVAS Vulnerability Test
# $Id: mdksa_2009_120.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:120 (openssl)
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
tag_insight = "Multiple security vulnerabilities has been identified and fixed
in OpenSSL:

The dtls1_buffer_record function in ssl/d1_pkt.c in OpenSSL 0.9.8k
and earlier 0.9.8 versions allows remote attackers to cause a denial
of service (memory consumption) via a large series of future epoch
DTLS records that are buffered in a queue, aka DTLS record buffer
limitation bug. (CVE-2009-1377)

Multiple memory leaks in the dtls1_process_out_of_seq_message function
in ssl/d1_both.c in OpenSSL 0.9.8k and earlier 0.9.8 versions allow
remote attackers to cause a denial of service (memory consumption)
via DTLS records that (1) are duplicates or (2) have sequence numbers
much greater than current sequence numbers, aka DTLS fragment handling
memory leak. (CVE-2009-1378)

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0, 2009.1";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:120";
tag_summary = "The remote host is missing an update to openssl
announced via advisory MDVSA-2009:120.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305336");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-1377", "CVE-2009-1378");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:120 (openssl)");



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
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8g~4.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8h~3.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8k~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

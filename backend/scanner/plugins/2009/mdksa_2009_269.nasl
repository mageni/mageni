# OpenVAS Vulnerability Test
# $Id: mdksa_2009_269.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:269 (mono)
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
tag_insight = "A vulnerability has been found and corrected in mono:

The XML HMAC signature system did not correctly check certain
lengths. If an attacker sent a truncated HMAC, it could bypass
authentication, leading to potential privilege escalation
(CVE-2009-0217).

This update fixes this vulnerability.

Affected: 2009.1";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:269";
tag_summary = "The remote host is missing an update to mono
announced via advisory MDVSA-2009:269.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305838");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2009-0217");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Mandrake Security Advisory MDVSA-2009:269 (mono)");



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
if ((res = isrpmvuln(pkg:"jay", rpm:"jay~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmono0", rpm:"libmono0~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmono-devel", rpm:"libmono-devel~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono", rpm:"mono~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-bytefx-data-mysql", rpm:"mono-bytefx-data-mysql~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-doc", rpm:"mono-doc~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"monodoc-core", rpm:"monodoc-core~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-ibm-data-db2", rpm:"mono-ibm-data-db2~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-wcf", rpm:"mono-wcf~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mono0", rpm:"lib64mono0~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mono-devel", rpm:"lib64mono-devel~2.2~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

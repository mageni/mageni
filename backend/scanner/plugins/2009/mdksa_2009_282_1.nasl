# OpenVAS Vulnerability Test
# $Id: mdksa_2009_282_1.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:282-1 (cups)
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
tag_insight = "For details on the issues addressed with this update,
please visit the referenced security advisories.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:282-1";
tag_summary = "The remote host is missing an update to cups
announced via advisory MDVSA-2009:282-1.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304824");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-1179", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-0949", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3608", "CVE-2009-3609");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:282-1 (cups)");



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
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler2", rpm:"libpoppler2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-glib2", rpm:"libpoppler-glib2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-qt2", rpm:"libpoppler-qt2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-qt4-2", rpm:"libpoppler-qt4-2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler-qt-devel", rpm:"libpoppler-qt-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cups", rpm:"php-cups~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~1.3.10~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler2", rpm:"lib64poppler2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-glib2", rpm:"lib64poppler-glib2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-qt2", rpm:"lib64poppler-qt2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-qt4-2", rpm:"lib64poppler-qt4-2~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-qt4-devel", rpm:"lib64poppler-qt4-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64poppler-qt-devel", rpm:"lib64poppler-qt-devel~0.6~3.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

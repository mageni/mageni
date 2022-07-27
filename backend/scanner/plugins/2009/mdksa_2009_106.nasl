# OpenVAS Vulnerability Test
# $Id: mdksa_2009_106.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:106 (libwmf)
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
tag_insight = "Use-after-free vulnerability in the embedded GD library in libwmf
0.2.8.4 allows context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
WMF file (CVE-2009-1364).

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:106";
tag_summary = "The remote host is missing an update to libwmf
announced via advisory MDVSA-2009:106.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309497");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-1364");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:106 (libwmf)");



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
if ((res = isrpmvuln(pkg:"libwmf0.2_7", rpm:"libwmf0.2_7~0.2.8.4~16.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7-devel", rpm:"libwmf0.2_7-devel~0.2.8.4~16.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.4~16.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7", rpm:"lib64wmf0.2_7~0.2.8.4~16.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7-devel", rpm:"lib64wmf0.2_7-devel~0.2.8.4~16.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7", rpm:"libwmf0.2_7~0.2.8.4~17.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7-devel", rpm:"libwmf0.2_7-devel~0.2.8.4~17.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.4~17.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7", rpm:"lib64wmf0.2_7~0.2.8.4~17.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7-devel", rpm:"lib64wmf0.2_7-devel~0.2.8.4~17.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7", rpm:"libwmf0.2_7~0.2.8.4~17.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7-devel", rpm:"libwmf0.2_7-devel~0.2.8.4~17.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.4~17.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7", rpm:"lib64wmf0.2_7~0.2.8.4~17.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7-devel", rpm:"lib64wmf0.2_7-devel~0.2.8.4~17.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7", rpm:"libwmf0.2_7~0.2.8~6.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7-devel", rpm:"libwmf0.2_7-devel~0.2.8~6.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8~6.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7", rpm:"lib64wmf0.2_7~0.2.8~6.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7-devel", rpm:"lib64wmf0.2_7-devel~0.2.8~6.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7", rpm:"libwmf0.2_7~0.2.8.3~6.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf0.2_7-devel", rpm:"libwmf0.2_7-devel~0.2.8.3~6.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.3~6.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7", rpm:"lib64wmf0.2_7~0.2.8.3~6.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wmf0.2_7-devel", rpm:"lib64wmf0.2_7-devel~0.2.8.3~6.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

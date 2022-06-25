# OpenVAS Vulnerability Test
# $Id: mdksa_2009_336.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:336 (koffice)
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
tag_insight = "Security vulnerabilities have been discovered and fixed in pdf
processing code embedded in koffice package (CVE-2009-3606 and
CVE-2009-3609).

This update fixes these vulnerabilities.

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:336";
tag_summary = "The remote host is missing an update to koffice
announced via advisory MDVSA-2009:336.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308630");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2009-3606", "CVE-2009-3609");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:336 (koffice)");



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
if ((res = isrpmvuln(pkg:"koffice", rpm:"koffice~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-karbon", rpm:"koffice-karbon~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kexi", rpm:"koffice-kexi~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kformula", rpm:"koffice-kformula~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kivio", rpm:"koffice-kivio~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-koshell", rpm:"koffice-koshell~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kplato", rpm:"koffice-kplato~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kpresenter", rpm:"koffice-kpresenter~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-krita", rpm:"koffice-krita~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kspread", rpm:"koffice-kspread~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kugar", rpm:"koffice-kugar~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-kword", rpm:"koffice-kword~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-progs", rpm:"koffice-progs~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-karbon", rpm:"libkoffice2-karbon~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-karbon-devel", rpm:"libkoffice2-karbon-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kexi", rpm:"libkoffice2-kexi~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kexi-devel", rpm:"libkoffice2-kexi-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kformula", rpm:"libkoffice2-kformula~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kformula-devel", rpm:"libkoffice2-kformula-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kivio", rpm:"libkoffice2-kivio~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kivio-devel", rpm:"libkoffice2-kivio-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-koshell", rpm:"libkoffice2-koshell~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kplato", rpm:"libkoffice2-kplato~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kpresenter", rpm:"libkoffice2-kpresenter~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kpresenter-devel", rpm:"libkoffice2-kpresenter-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-krita", rpm:"libkoffice2-krita~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-krita-devel", rpm:"libkoffice2-krita-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kspread", rpm:"libkoffice2-kspread~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kspread-devel", rpm:"libkoffice2-kspread-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kugar", rpm:"libkoffice2-kugar~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kugar-devel", rpm:"libkoffice2-kugar-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kword", rpm:"libkoffice2-kword~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-kword-devel", rpm:"libkoffice2-kword-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-progs", rpm:"libkoffice2-progs~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkoffice2-progs-devel", rpm:"libkoffice2-progs-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-karbon", rpm:"lib64koffice2-karbon~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-karbon-devel", rpm:"lib64koffice2-karbon-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kexi", rpm:"lib64koffice2-kexi~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kexi-devel", rpm:"lib64koffice2-kexi-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kformula", rpm:"lib64koffice2-kformula~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kformula-devel", rpm:"lib64koffice2-kformula-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kivio", rpm:"lib64koffice2-kivio~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kivio-devel", rpm:"lib64koffice2-kivio-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-koshell", rpm:"lib64koffice2-koshell~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kplato", rpm:"lib64koffice2-kplato~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kpresenter", rpm:"lib64koffice2-kpresenter~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kpresenter-devel", rpm:"lib64koffice2-kpresenter-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-krita", rpm:"lib64koffice2-krita~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-krita-devel", rpm:"lib64koffice2-krita-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kspread", rpm:"lib64koffice2-kspread~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kspread-devel", rpm:"lib64koffice2-kspread-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kugar", rpm:"lib64koffice2-kugar~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kugar-devel", rpm:"lib64koffice2-kugar-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kword", rpm:"lib64koffice2-kword~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-kword-devel", rpm:"lib64koffice2-kword-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-progs", rpm:"lib64koffice2-progs~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64koffice2-progs-devel", rpm:"lib64koffice2-progs-devel~1.6.3~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

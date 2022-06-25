# OpenVAS Vulnerability Test
# $Id: mdksa_2009_272.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:272 (libmikmod)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in libmikmod:

libmikmod 3.1.9 through 3.2.0, as used by MikMod, SDL-mixer, and
possibly other products, relies on the channel count of the last
loaded song, rather than the currently playing song, for certain
playback calculations, which allows user-assisted attackers to cause
a denial of service (application crash) by loading multiple songs
(aka MOD files) with different numbers of channels (CVE-2007-6720).

libmikmod 3.1.11 through 3.2.0, as used by MikMod and possibly other
products, allows user-assisted attackers to cause a denial of service
(application crash) by loading an XM file (CVE-2009-0179).

This update fixes these vulnerabilities.

Affected: 2008.1, 2009.0, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:272";
tag_summary = "The remote host is missing an update to libmikmod
announced via advisory MDVSA-2009:272.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310952");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2007-6720", "CVE-2009-0179");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:272 (libmikmod)");



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
if ((res = isrpmvuln(pkg:"libmikmod2", rpm:"libmikmod2~3.1.11a~10.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmikmod-devel", rpm:"libmikmod-devel~3.1.11a~10.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mikmod2", rpm:"lib64mikmod2~3.1.11a~10.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mikmod-devel", rpm:"lib64mikmod-devel~3.1.11a~10.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmikmod3", rpm:"libmikmod3~3.2.0~0.beta2.2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmikmod-devel", rpm:"libmikmod-devel~3.2.0~0.beta2.2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mikmod3", rpm:"lib64mikmod3~3.2.0~0.beta2.2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mikmod-devel", rpm:"lib64mikmod-devel~3.2.0~0.beta2.2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmikmod3", rpm:"libmikmod3~3.2.0~0.beta2.2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmikmod-devel", rpm:"libmikmod-devel~3.2.0~0.beta2.2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mikmod3", rpm:"lib64mikmod3~3.2.0~0.beta2.2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mikmod-devel", rpm:"lib64mikmod-devel~3.2.0~0.beta2.2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

# OpenVAS Vulnerability Test
# $Id: mdksa_2009_327.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:327 (clamav)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in clamav:

Unspecified vulnerability in ClamAV before 0.95 allows remote
attackers to bypass detection of malware via a modified RAR archive
(CVE-2009-1241).

libclamav/pe.c in ClamAV before 0.95 allows remote attackers to cause
a denial of service (crash) via a crafted EXE file that triggers a
divide-by-zero error (CVE-2008-6680).

libclamav/untar.c in ClamAV before 0.95 allows remote attackers to
cause a denial of service (infinite loop) via a crafted file that
causes (1) clamd and (2) clamscan to hang (CVE-2009-1270).

The CLI_ISCONTAINED macro in libclamav/others.h in ClamAV before 0.95.1
allows remote attackers to cause a denial of service (application
crash) via a malformed file with UPack encoding (CVE-2009-1371).

Stack-based buffer overflow in the cli_url_canon function in
libclamav/phishcheck.c in ClamAV before 0.95.1 allows remote attackers
to cause a denial of service (application crash) and possibly execute
arbitrary code via a crafted URL (CVE-2009-1372).

Important notice about this upgrade: clamav-0.95+ bundles support
for RAR v3 in libclamav which is a license violation as the RAR v3
license and the GPL license is not compatible. As a consequence to
this Mandriva has been forced to remove the RAR v3 code.

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update provides clamav 0.95.2, which is not vulnerable to these
issues. Additionally klamav-0.46 is being provided that has support
for clamav-0.95+.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:327";
tag_summary = "The remote host is missing an update to clamav
announced via advisory MDVSA-2009:327.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306381");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-1241", "CVE-2008-6680", "CVE-2009-1270", "CVE-2009-1371", "CVE-2009-1372");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:327 (clamav)");



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
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"klamav", rpm:"klamav~0.46~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav6", rpm:"libclamav6~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav6", rpm:"lib64clamav6~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.95.2~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

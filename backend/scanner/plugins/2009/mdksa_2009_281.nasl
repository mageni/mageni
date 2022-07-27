# OpenVAS Vulnerability Test
# $Id: mdksa_2009_281.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:281 (cups)
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
tag_insight = "Multiple integer overflows in the JBIG2 decoder in Xpdf 3.02pl2
and earlier, CUPS 1.3.9 and earlier, and other products allow
remote attackers to cause a denial of service (crash) via a
crafted PDF file, related to (1) JBIG2Stream::readSymbolDictSeg, (2)
JBIG2Stream::readSymbolDictSeg, and (3) JBIG2Stream::readGenericBitmap
(CVE-2009-0146, CVE-2009-0147).

Integer overflow in the TIFF image decoding routines in CUPS 1.3.9 and
earlier allows remote attackers to cause a denial of service (daemon
crash) and possibly execute arbitrary code via a crafted TIFF image,
which is not properly handled by the (1) _cupsImageReadTIFF function
in the imagetops filter and (2) imagetoraster filter, leading to a
heap-based buffer overflow (CVE-2009-0163).

Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier,
as used in Poppler and other products, when running on Mac OS X,
has unspecified impact, related to g*allocn (CVE-2009-0165).

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
and other products allows remote attackers to cause a denial of service
(crash) via a crafted PDF file that triggers a free of uninitialized
memory (CVE-2009-0166).

Multiple integer overflows in the pdftops filter in CUPS 1.1.17,
1.1.22, and 1.3.7 allow remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
PDF file that triggers a heap-based buffer overflow, possibly
related to (1) Decrypt.cxx, (2) FoFiTrueType.cxx, (3) gmem.c,
(4) JBIG2Stream.cxx, and (5) PSOutputDev.cxx in pdftops/. NOTE:
the JBIG2Stream.cxx vector may overlap CVE-2009-1179 (CVE-2009-0791).

The ippReadIO function in cups/ipp.c in cupsd in CUPS before 1.3.10
does not properly initialize memory for IPP request packets, which
allows remote attackers to cause a denial of service (NULL pointer
dereference and daemon crash) via a scheduler request with two
consecutive IPP_TAG_UNSUPPORTED tags (CVE-2009-0949).

Two integer overflow flaws were found in the CUPS pdftops filter. An
attacker could create a malicious PDF file that would cause pdftops
to crash or, potentially, execute arbitrary code as the lp user if
the file was printed. (CVE-2009-3608, CVE-2009-3609)

This update corrects the problems.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:281";
tag_summary = "The remote host is missing an update to cups
announced via advisory MDVSA-2009:281.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309088");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-1179", "CVE-2009-0791", "CVE-2009-0949", "CVE-2009-3608", "CVE-2009-3609");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:281 (cups)");



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
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cups", rpm:"php-cups~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~1.2.4~0.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

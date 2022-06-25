# OpenVAS Vulnerability Test
# $Id: mdksa_2009_330.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:330 (kdelibs)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in kdelibs:

The gdtoa (aka new dtoa) implementation in gdtoa/misc.c in
libc in FreeBSD 6.4 and 7.2, NetBSD 5.0, and OpenBSD 4.5 allows
context-dependent attackers to cause a denial of service (application
crash) or possibly have unspecified other impact via a large precision
value in the format argument to a printf function, related to an
array overrun. (CVE-2009-0689)

The JavaScript garbage collector in WebKit in Apple Safari before
4.0, iPhone OS 1.0 through 2.2.1, and iPhone OS for iPod touch 1.1
through 2.2.1 does not properly handle allocation failures, which
allows remote attackers to execute arbitrary code or cause a denial
of service (memory corruption and application crash) via a crafted
HTML document that triggers write access to an offset of a NULL
pointer. (CVE-2009-1687)

Use-after-free vulnerability in WebKit, as used in Apple Safari
before 4.0, iPhone OS 1.0 through 2.2.1, iPhone OS for iPod touch 1.1
through 2.2.1, Google Chrome 1.0.154.53, and possibly other products,
allows remote attackers to execute arbitrary code or cause a denial
of service (memory corruption and application crash) by setting an
unspecified property of an HTML tag that causes child elements to
be freed and later accessed when an HTML error occurs, related to
recursion in certain DOM event handlers. (CVE-2009-1690)

WebKit in Apple Safari before 4.0, iPhone OS 1.0 through 2.2.1,
and iPhone OS for iPod touch 1.1 through 2.2.1 does not initialize a
pointer during handling of a Cascading Style Sheets (CSS) attr function
call with a large numerical argument, which allows remote attackers to
execute arbitrary code or cause a denial of service (memory corruption
and application crash) via a crafted HTML document. (CVE-2009-1698)

WebKit in Apple Safari before 4.0.2, KHTML in kdelibs in KDE, QtWebKit
(aka Qt toolkit), and possibly other products does not properly handle
numeric character references, which allows remote attackers to execute
arbitrary code or cause a denial of service (memory corruption and
application crash) via a crafted HTML document. (CVE-2009-1725)

KDE Konqueror allows remote attackers to cause a denial of service
(memory consumption) via a large integer value for the length property
of a Select object, a related issue to CVE-2009-1692. (CVE-2009-2537)

KDE KSSL in kdelibs 3.5.4, 4.2.4, and 4.3 does not properly handle a
'\0' (NUL) character in a domain name in the Subject Alternative Name
field of an X.509 certificate, which allows man-in-the-middle attackers
to spoof arbitrary SSL servers via a crafted certificate issued by a
legitimate Certification Authority, a related issue to CVE-2009-2408
(CVE-2009-2702).

This update provides a solution to this vulnerability.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:330";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory MDVSA-2009:330.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308398");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-0689", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1725", "CVE-2009-1692", "CVE-2009-2537", "CVE-2009-2408", "CVE-2009-2702");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:330 (kdelibs)");



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
if ((res = isrpmvuln(pkg:"kdelibs-arts", rpm:"kdelibs-arts~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-common", rpm:"kdelibs-common~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-devel-doc", rpm:"kdelibs-devel-doc~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdecore4", rpm:"libkdecore4~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdecore4-devel", rpm:"libkdecore4-devel~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdecore4", rpm:"lib64kdecore4~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdecore4-devel", rpm:"lib64kdecore4-devel~3.5.4~2.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

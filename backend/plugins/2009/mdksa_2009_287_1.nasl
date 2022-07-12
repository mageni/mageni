# OpenVAS Vulnerability Test
# $Id: mdksa_2009_287_1.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:287-1 (xpdf)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in xpdf:

Integer overflow in the SplashBitmap::SplashBitmap function in Xpdf 3.x
before 3.02pl4 and Poppler before 0.12.1 might allow remote attackers
to execute arbitrary code via a crafted PDF document that triggers a
heap-based buffer overflow.  NOTE: some of these details are obtained
from third party information.  NOTE: this issue reportedly exists
because of an incomplete fix for CVE-2009-1188 (CVE-2009-3603).

The Splash::drawImage function in Splash.cc in Xpdf 2.x and 3.x
before 3.02pl4, and Poppler 0.x, as used in GPdf and kdegraphics KPDF,
does not properly allocate memory, which allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via a crafted PDF document that triggers a NULL pointer
dereference or a heap-based buffer overflow (CVE-2009-3604).

Integer overflow in the PSOutputDev::doImageL1Sep function in Xpdf
before 3.02pl4, and Poppler 0.x, as used in kdegraphics KPDF, might
allow remote attackers to execute arbitrary code via a crafted PDF
document that triggers a heap-based buffer overflow (CVE-2009-3606).

Integer overflow in the ObjectStream::ObjectStream function in XRef.cc
in Xpdf 3.x before 3.02pl4 and Poppler before 0.12.1, as used in
GPdf, kdegraphics KPDF, CUPS pdftops, and teTeX, might allow remote
attackers to execute arbitrary code via a crafted PDF document that
triggers a heap-based buffer overflow (CVE-2009-3608).

Integer overflow in the ImageStream::ImageStream function in Stream.cc
in Xpdf before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, and CUPS pdftops, allows remote attackers to
cause a denial of service (application crash) via a crafted PDF
document that triggers a NULL pointer dereference or buffer over-read
(CVE-2009-3609).

This update fixes these vulnerabilities.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:287-1";
tag_summary = "The remote host is missing an update to xpdf
announced via advisory MDVSA-2009:287-1.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304459");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:287-1 (xpdf)");



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
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~3.02~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-tools", rpm:"xpdf-tools~3.02~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

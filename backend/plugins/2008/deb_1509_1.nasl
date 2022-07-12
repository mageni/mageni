# OpenVAS Vulnerability Test
# $Id: deb_1509_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1509-1 (koffice)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Several vulnerabilities have been discovered in xpdf code that is
embedded in koffice, an integrated office suite for KDE.  These flaws
could allow an attacker to execute arbitrary code by inducing the user
to import a specially crafted PDF document.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-4352

Array index error in the DCTStream::readProgressiveDataUnit method in
xpdf/Stream.cc in Xpdf 3.02pl1, as used in poppler, teTeX, KDE, KOffice,
CUPS, and other products, allows remote attackers to trigger memory
corruption and execute arbitrary code via a crafted PDF file.

CVE-2007-5392

Integer overflow in the DCTStream::reset method in xpdf/Stream.cc in
Xpdf 3.02p11 allows remote attackers to execute arbitrary code via a
crafted PDF file, resulting in a heap-based buffer overflow.

CVE-2007-5393

Heap-based buffer overflow in the CCITTFaxStream::lookChar method in
xpdf/Stream.cc in Xpdf 3.02p11 allows remote attackers to execute
arbitrary code via a PDF file that contains a crafted CCITTFaxDecode
filter.

For the stable distribution (etch), these problems have been fixed in version
1:1.6.1-2etch2.

Updates for the old stable distribution (sarge), will be made available
as soon as possible.

We recommend that you upgrade your koffice package.";
tag_summary = "The remote host is missing an update to koffice
announced via advisory DSA 1509-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201509-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301194");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1509-1 (koffice)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"koffice-data", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kword-data", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kivio-data", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koffice-doc", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koffice-doc-html", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koffice", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kpresenter-data", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krita-data", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koffice-dbg", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kword", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kexi", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koffice-dev", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"karbon", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koshell", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kspread", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kivio", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kplato", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kugar", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kchart", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krita", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kpresenter", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kthesaurus", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"koffice-libs", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kformula", ver:"1.6.1-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

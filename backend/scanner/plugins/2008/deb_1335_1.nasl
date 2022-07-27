# OpenVAS Vulnerability Test
# $Id: deb_1335_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1335-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "Several remote vulnerabilities have been discovered in Gimp, the GNU Image
Manipulation Program, which might lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2006-4519

Sean Larsson discovered several integer overflows in the processing
code for DICOM, PNM, PSD, RAS, XBM and XWD images, which might lead
to the execution of arbitrary code if a user is tricked into opening
such a malformed media file.

CVE-2007-2949

Stefan Cornelius discovered an integer overflow in the processing
code for PSD images, which might lead to the execution of arbitrary
code if a user is tricked into opening such a malformed media file.

For the oldstable distribution (sarge) these problems have been fixed in
version 2.2.6-1sarge4. Packages for mips and mipsel are not yet
available.

For the stable distribution (etch) these problems have been fixed
in version 2.2.13-1etch4. Packages for mips are not yet available.

For the unstable distribution (sid) these problems have been fixed in
version 2.2.17-1.

We recommend that you upgrade your gimp packages.";
tag_summary = "The remote host is missing an update to gimp
announced via advisory DSA 1335-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201335-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301881");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-4519", "CVE-2007-2949");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1335-1 (gimp)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"gimp-data", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp1.2", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-helpbrowser", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-python", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-svg", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.2.6-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-data", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-dbg", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-helpbrowser", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-python", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gimp-svg", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.2.13-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

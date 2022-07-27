# OpenVAS Vulnerability Test
# $Id: deb_1814_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1814-1 (libsndfile)
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
tag_insight = "Two vulnerabilities have been found in libsndfile, a library to read
and write sampled audio data.  The Common Vulnerabilities and Exposures
project identified the following problems:

Tobias Klein discovered that the VOC parsing routines suffer of a heap-based
buffer overflow which can be triggered by an attacker via a crafted VOC
header (CVE-2009-1788).

The vendor discovered that the  AIFF parsing routines suffer of a heap-based
buffer overflow similar to CVE-2009-1788 which can be triggered by an attacker
via a crafted AIFF header (CVE-2009-1791).

In both cases the overflowing data is not completely attacker controlled but
still leads to application crashes or under some circumstances might still
lead to arbitrary code execution.


For the oldstable distribution (etch), this problem has been fixed in
version 1.0.16-2+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.17-4+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.0.20-1.


We recommend that you upgrade your libsndfile packages.";
tag_summary = "The remote host is missing an update to libsndfile
announced via advisory DSA 1814-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201814-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310349");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_cve_id("CVE-2009-1788", "CVE-2009-1791");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1814-1 (libsndfile)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.16-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.16-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.16-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.17-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.17-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.17-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

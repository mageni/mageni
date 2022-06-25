# OpenVAS Vulnerability Test
# $Id: deb_1493_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1493-2 (sdl-image1.2)
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
tag_insight = "An oversight led to the version number of the Debian 4.0 `Etch' update
for advisory DSA 1493-1 being lower than the version in the main archive,
making it uninstallable. This update corrects the version number.
For reference the full advisory is quoted below:

Several local/remote vulnerabilities have been discovered in the image
loading library for the Simple DirectMedia Layer 1.2. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6697

Gynvael Coldwind discovered a buffer overflow in GIF image parsing,
which could result in denial of service and potentially the
execution of arbitrary code.

CVE-2008-0544

It was discovered that a buffer overflow in IFF ILBM image parsing
could result in denial of service and potentially the execution of
arbitrary code.

For the stable distribution (etch), these problems have been fixed in
version 1.2.5-2+etch1.

For the old stable distribution (sarge), these problems have been fixed
in version 1.2.4-1etch1. Due to a copy & paste error etch1 was appended
to the version number instead of sarge1. Since the update is otherwise
technically correct, the update was not rebuilt to the buildd network.

We recommend that you upgrade your sdl-image1.2 packages.";
tag_summary = "The remote host is missing an update to sdl-image1.2
announced via advisory DSA 1493-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201493-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301024");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-03-19 20:30:32 +0100 (Wed, 19 Mar 2008)");
 script_cve_id("CVE-2007-6697", "CVE-2008-0554", "CVE-2008-0544");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1493-2 (sdl-image1.2)");



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
if ((res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.4-1etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.4-1etch1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.5-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.5-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

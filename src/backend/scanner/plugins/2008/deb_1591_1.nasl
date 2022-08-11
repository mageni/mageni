# OpenVAS Vulnerability Test
# $Id: deb_1591_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1591-1 (libvorbis)
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
tag_insight = "Several local (remote) vulnerabilities have been discovered in libvorbis,
a library for the Vorbis general-purpose compressed audio codec. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1419

libvorbis does not properly handle a zero value which allows remote
attackers to cause a denial of service (crash or infinite loop) or
trigger an integer overflow.

CVE-2008-1420

Integer overflow in libvorbis allows remote attackers to execute
arbitrary code via a crafted OGG file, which triggers a heap overflow.

CVE-2008-1423

Integer overflow in libvorbis allows remote attackers to cause a denial
of service (crash) or execute arbitrary code via a crafted OGG file
which triggers a heap overflow.

For the stable distribution (etch), these problems have been fixed in version
1.1.2.dfsg-1.4.

For the unstable distribution (sid), these problems have been fixed in
version 1.2.0.dfsg-3.1.

We recommend that you upgrade your libvorbis package.";
tag_summary = "The remote host is missing an update to libvorbis
announced via advisory DSA 1591-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201591-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303146");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-06-11 18:37:44 +0200 (Wed, 11 Jun 2008)");
 script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1591-1 (libvorbis)");



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
if ((res = isdpkgvuln(pkg:"libvorbisenc2", ver:"1.1.2.dfsg-1.4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis0a", ver:"1.1.2.dfsg-1.4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisfile3", ver:"1.1.2.dfsg-1.4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis-dev", ver:"1.1.2.dfsg-1.4", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

# OpenVAS Vulnerability Test
# $Id: deb_1819_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1819-1 (vlc)
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
tag_insight = "Several vulnerabilities have been discovered in vlc, a multimedia player
and streamer. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-1768

Drew Yao discovered that multiple integer overflows in the MP4 demuxer,
Real demuxer and Cinepak codec can lead to the execution of arbitrary
code.

CVE-2008-1769

Drew Yao discovered that the Cinepak codec is prone to a memory
corruption, which can be triggered by a crafted Cinepak file.

CVE-2008-1881

Luigi Auriemma discovered that it is possible to execute arbitrary code
via a long subtitle in an SSA file.

CVE-2008-2147

It was discovered that vlc is prone to a search path vulnerability,
which allows local users to perform privilege escalations.

CVE-2008-2430

Alin Rad Pop discovered that it is possible to execute arbitrary code
when opening a WAV file containing a large fmt chunk.

CVE-2008-3794

Pnar Yanarda discovered that it is possible to execute arbitrary code
when opening a crafted mmst link.

CVE-2008-4686

Tobias Klein discovered that it is possible to execute arbitrary code
when opening a crafted .ty file.

CVE-2008-5032

Tobias Klein discovered that it is possible to execute arbitrary code
when opening an invalid CUE image file with a crafted header.


For the oldstable distribution (etch), these problems have been fixed
in version 0.8.6-svn20061012.debian-5.1+etch3.

For the stable distribution (lenny), these problems have been fixed in
version 0.8.6.h-4+lenny2, which was already included in the lenny
release.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 0.8.6.h-5.


We recommend that you upgrade your vlc packages.";
tag_summary = "The remote host is missing an update to vlc
announced via advisory DSA 1819-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201819-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305724");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_cve_id("CVE-2008-1768", "CVE-2008-1769", "CVE-2008-1881", "CVE-2008-2147", "CVE-2008-2430", "CVE-2008-3794", "CVE-2008-4686", "CVE-2008-5032");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1819-1 (vlc)");



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
if ((res = isdpkgvuln(pkg:"wxvlc", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-alsa", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-nox", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

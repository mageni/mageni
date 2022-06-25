# OpenVAS Vulnerability Test
# $Id: deb_1332_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1332-1
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
tag_insight = "Several remote vulnerabilities have been discovered in the VideoLan
multimedia player and streamer, which may lead to the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-3316

David Thiel discovered that several format string vulnerabilities may
lead to the execution of arbitrary code.

CVE-2007-3467

David Thiel discovered an integer overflow in the WAV processing code.

This update also fixes several crashes, which can be triggered through
malformed media files.

For the oldstable distribution (sarge) these problems have been fixed in
version 0.8.1.svn20050314-1sarge3. Packages for the powerpc architecture
are not yet available. They will be provided later.

For the stable distribution (etch) these problems have been fixed
in version 0.8.6-svn20061012.debian-5etch1.

For the unstable distribution (sid) these problems have been fixed in
version 0.8.6.c-1.

We recommend that you upgrade your vlc packages.";
tag_summary = "The remote host is missing an update to vlc
announced via advisory DSA 1332-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201332-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301547");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-3316", "CVE-2007-3467", "CVE-2007-3468");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1332-1 (vlc)");



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
if ((res = isdpkgvuln(pkg:"gnome-vlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gvlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qvlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-alsa", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-esd", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-ggi", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-gnome", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-gtk", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-alsa", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-qt", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-sdl", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wxvlc", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-glide", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.1.svn20050314-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-alsa", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wxvlc", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-nox", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.6-svn20061012.debian-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

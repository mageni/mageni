# OpenVAS Vulnerability Test
# $Id: deb_1543_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1543-1 (vlc)
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
tag_insight = "Luigi Auriemma, Alin Rad Pop, Rémi Denis-Courmont, Quovodis, Guido
Landi, Felipe Manzano, Anibal Sacco and others discovered multiple
vulnerabilities in vlc, an application for playback and streaming of
audio and video.  In the worst case, these weaknesses permit a remote,
unauthenticated attacker to execute arbitrary code with the privileges
of the user running vlc.

The Common Vulnerabilities and Exposures project identifies the
following eight problems:

CVE-2007-6681

A buffer overflow vulnerability in subtitle handling allows an
attacker to execute arbitrary code through the opening of a
maliciously crafted MicroDVD, SSA or Vplayer file.

CVE-2007-6682

A format string vulnerability in the HTTP-based remote control
facility of the vlc application allows a remote, unauthenticated
attacker to execute arbitrary code.

CVE-2007-6683

Insecure argument validation allows a remote attacker to overwrite
arbitrary files writable by the user running vlc, if a maliciously
crafted M3U playlist or MP3 audio file is opened.

CVE-2008-0295, CVE-2008-0296

Heap buffer overflows in RTSP stream and session description
protocol (SDP) handling allow an attacker to execute arbitrary
code if a maliciously-crafted RTSP stream is played.

CVE-2008-0073

Insufficient integer bounds checking in SDP handling allows the
execution of arbitrary code through a maliciously crafted SDP
stream ID parameter in an RTSP stream.

CVE-2008-0984

Insufficient integrity checking in the MP4 demuxer allows a remote
attacker to overwrite arbitrary memory and execute arbitrary code
if a maliciously-crafted MP4 file is opened.

CVE-2008-1489

An integer overflow vulnerability in MP4 handling allows a remote
attacker to cause a heap buffer overflow, inducing a crash and
possibly the execution of arbitrary code if a maliciously-crafted
MP4 file is opened.

For the stable distribution (etch), these problems have been fixed in
version 0.8.6-svn20061012.debian-5.1+etch2.

For the unstable distribution (sid), these problems have been fixed in
version 0.6.8.e-2.

We recommend that you upgrade your vlc packages.";
tag_summary = "The remote host is missing an update to vlc
announced via advisory DSA 1543-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201543-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302805");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
 script_cve_id("CVE-2007-6681", "CVE-2007-6682", "CVE-2007-6683", "CVE-2008-0295", "CVE-2008-0296", "CVE-2008-0073", "CVE-2008-0984", "CVE-2008-1489");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1543-1 (vlc)");



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
if ((res = isdpkgvuln(pkg:"vlc-plugin-alsa", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wxvlc", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-nox", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.6-svn20061012.debian-5.1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

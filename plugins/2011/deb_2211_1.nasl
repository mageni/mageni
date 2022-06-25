# OpenVAS Vulnerability Test
# $Id: deb_2211_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2211-1 (vlc)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69555");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3275", "CVE-2010-3276", "CVE-2010-0522", "CVE-2010-1441", "CVE-2010-1442", "CVE-2011-0531");
  script_name("Debian Security Advisory DSA 2211-1 (vlc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202211-1");
  script_tag(name:"insight", value:"Ricardo Narvaja discovered that missing input sanitising in VLC, a
multimedia player and streamer, could lead to the execution of arbitrary
code if a user is tricked into opening a malformed media file.

This update also provides updated packages for oldstable (lenny) for
vulnerabilities, which have already been addressed in Debian stable
(squeeze), either during the freeze or in DSA-2159.
(CVE-2010-0522, CVE-2010-1441, CVE-2010-1442, CVE-2011-0531)

For the oldstable distribution (lenny), this problem has been fixed in
version 0.8.6.h-4+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.3-1squeeze4.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.8-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your vlc packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to vlc
announced via advisory DSA 2211-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libvlc0", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-nox", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.6.h-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvlc-dev", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvlc5", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvlccore-dev", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvlccore4", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-data", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-dbg", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-nox", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-fluidsynth", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-jack", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-notify", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-pulse", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-svg", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vlc-plugin-zvbi", ver:"1.1.3-1squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
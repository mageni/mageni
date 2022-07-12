# OpenVAS Vulnerability Test
# $Id: deb_3819.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3819-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.703819");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2016-9811", "CVE-2017-5837", "CVE-2017-5839", "CVE-2017-5842", "CVE-2017-5844");
  script_name("Debian Security Advisory DSA 3819-1 (gst-plugins-base1.0 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-27 00:00:00 +0200 (Mon, 27 Mar 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3819.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"gst-plugins-base1.0 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 1.4.4-2+deb8u1.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 1.10.4-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.10.4-1.

We recommend that you upgrade your gst-plugins-base1.0 packages.");
  script_tag(name:"summary", value:"Hanno Boeck discovered multiple vulnerabilities in the GStreamer media
framework and its codecs and demuxers, which may result in denial of
service or the execution of arbitrary code if a malformed media file is
opened.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gir1.2-gst-plugins-base-1.0", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-alsa:amd64", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-alsa:i386", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base:amd64", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base:i386", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-apps", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-dbg:amd64", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-dbg:i386", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-doc", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-x:amd64", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-x:i386", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-0:amd64", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-0:i386", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-dev", ver:"1.4.4-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gir1.2-gst-plugins-base-1.0", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-alsa:amd64", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-alsa:i386", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base:amd64", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base:i386", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-apps", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-dbg:amd64", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-dbg:i386", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-doc", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-x:amd64", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gstreamer1.0-x:i386", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-0:amd64", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-0:i386", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-dev", ver:"1.10.4-1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
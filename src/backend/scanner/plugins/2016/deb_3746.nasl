# OpenVAS Vulnerability Test
# $Id: deb_3746.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3746-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703746");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-8808", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-3714",
                  "CVE-2016-3715", "CVE-2016-5118", "CVE-2016-5240", "CVE-2016-7800",
                  "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8682", "CVE-2016-8683",
                  "CVE-2016-8684", "CVE-2016-9830");
  script_name("Debian Security Advisory DSA 3746-1 (graphicsmagick - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-24 00:00:00 +0100 (Sat, 24 Dec 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3746.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"graphicsmagick on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in version 1.3.20-3+deb8u2. For the testing distribution (stretch), these problems (with the exception of CVE-2016-9830 ) have been fixed in version 1.3.25-5.
For the unstable distribution (sid), these problems have been fixed in version 1.3.25-6.
We recommend that you upgrade your graphicsmagick packages.");

  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in GraphicsMagick, a collection of image processing tool, which can
cause denial of service attacks, remote file deletion, and remote command execution.

This security update removes the full support of PLT/Gnuplot decoder to
prevent Gnuplot-shell based shell exploits for fixing the
CVE-2016-3714 vulnerability.

The undocumented TMP magick prefix no longer removes the argument file
after it has been read for fixing the CVE-2016-3715 vulnerability. Since the TMP
feature was originally implemented, GraphicsMagick added a temporary file
management subsystem which assures that temporary files are removed so this
feature is not needed.

Remove support for reading input from a shell command, or writing output
to a shell command, by prefixing the specified filename (containing the
command) for fixing the
CVE-2016-5118 vulnerability.

CVE-2015-8808
Gustavo Grieco discovered an out of bound read in the parsing of GIF
files which may cause denial of service.

CVE-2016-2317
Gustavo Grieco discovered a stack buffer overflow and two heap buffer
overflows while processing SVG images which may cause denial of service.

CVE-2016-2318
Gustavo Grieco discovered several segmentation faults while processing
SVG images which may cause denial of service.

CVE-2016-5240
Gustavo Grieco discovered an endless loop problem caused by negative
stroke-dasharray arguments while parsing SVG files which may cause
denial of service.

CVE-2016-7800
Marco Grassi discovered an unsigned underflow leading to heap overflow
when parsing 8BIM chunk often attached to JPG files which may cause
denial of service.

CVE-2016-7996
Moshe Kaplan discovered that there is no check that the provided
colormap is not larger than 256 entries in the WPG reader which may
cause denial of service.

CVE-2016-7997
Moshe Kaplan discovered that an assertion is thrown for some files in
the WPG reader due to a logic error which may cause denial of service.

CVE-2016-8682
Agostino Sarubbo of Gentoo discovered a stack buffer read overflow
while reading the SCT header which may cause denial of service.

CVE-2016-8683
Agostino Sarubbo of Gentoo discovered a memory allocation failure in the
PCX coder which may cause denial of service.

CVE-2016-8684
Agostino Sarubbo of Gentoo discovered a memory allocation failure in the
SGI coder which may cause denial of service.

CVE-2016-9830
Agostino Sarubbo of Gentoo discovered a memory allocation failure in
MagickRealloc() function which may cause denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.20-3+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4321.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4321-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704321");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-10794", "CVE-2017-10799", "CVE-2017-10800", "CVE-2017-11102", "CVE-2017-11139",
                "CVE-2017-11140", "CVE-2017-11403", "CVE-2017-11636", "CVE-2017-11637", "CVE-2017-11638",
                "CVE-2017-11641", "CVE-2017-11642", "CVE-2017-11643", "CVE-2017-11722", "CVE-2017-12935",
                "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065",
                "CVE-2017-13134", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-13776", "CVE-2017-13777",
                "CVE-2017-14314", "CVE-2017-14504", "CVE-2017-14733", "CVE-2017-14994", "CVE-2017-14997",
                "CVE-2017-15238", "CVE-2017-15277", "CVE-2017-15930", "CVE-2017-16352", "CVE-2017-16353",
                "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-16669", "CVE-2017-17498", "CVE-2017-17500",
                "CVE-2017-17501", "CVE-2017-17502", "CVE-2017-17503", "CVE-2017-17782", "CVE-2017-17783",
                "CVE-2017-17912", "CVE-2017-17913", "CVE-2017-17915", "CVE-2017-18219", "CVE-2017-18220",
                "CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231", "CVE-2018-5685", "CVE-2018-6799",
                "CVE-2018-9018");
  script_name("Debian Security Advisory DSA 4321-1 (graphicsmagick - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-16 00:00:00 +0200 (Tue, 16 Oct 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4321.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"graphicsmagick on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 1.3.30+hg15796-1~deb9u1.

We recommend that you upgrade your graphicsmagick packages.

For the detailed security status of graphicsmagick please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/graphicsmagick");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in GraphicsMagick, a set of
command-line applications to manipulate image files, which could result
in denial of service or the execution of arbitrary code if malformed
image files are processed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick++-q16-12", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
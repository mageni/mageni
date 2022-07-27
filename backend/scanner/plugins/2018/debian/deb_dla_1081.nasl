###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1081.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1081-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891081");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-10928", "CVE-2017-10995", "CVE-2017-11141", "CVE-2017-11170", "CVE-2017-11188", "CVE-2017-11352", "CVE-2017-11360", "CVE-2017-11446", "CVE-2017-11448", "CVE-2017-11449", "CVE-2017-11450", "CVE-2017-11478", "CVE-2017-11505", "CVE-2017-11523", "CVE-2017-11524", "CVE-2017-11525", "CVE-2017-11526", "CVE-2017-11527", "CVE-2017-11528", "CVE-2017-11529", "CVE-2017-11530", "CVE-2017-11531", "CVE-2017-11532", "CVE-2017-11533", "CVE-2017-11534", "CVE-2017-11535", "CVE-2017-11537", "CVE-2017-11539", "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-11751", "CVE-2017-11752", "CVE-2017-12140", "CVE-2017-12418", "CVE-2017-12427", "CVE-2017-12428", "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12431", "CVE-2017-12432", "CVE-2017-12433", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12564", "CVE-2017-12565", "CVE-2017-12566", "CVE-2017-12587", "CVE-2017-12640", "CVE-2017-12641", "CVE-2017-12642", "CVE-2017-12643", "CVE-2017-12654", "CVE-2017-12664", "CVE-2017-12665", "CVE-2017-12668", "CVE-2017-12670", "CVE-2017-12674", "CVE-2017-12675", "CVE-2017-12676", "CVE-2017-12877", "CVE-2017-12983", "CVE-2017-13133", "CVE-2017-13134", "CVE-2017-13139", "CVE-2017-13142", "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13146", "CVE-2017-13658", "CVE-2017-8352", "CVE-2017-9144", "CVE-2017-9501");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1081-1] imagemagick security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00031.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"imagemagick on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
6.7.7.10-5+deb7u16.

We recommend that you upgrade your imagemagick packages.");
  script_tag(name:"summary", value:"This updates fixes numerous vulnerabilities in imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service, memory disclosure or the
execution of arbitrary code if malformed DPX, RLE, CIN, DIB, EPT, MAT,
VST, PNG, JNG, MNG, DVJU, JPEG, TXT, PES, MPC, UIL, PS, PALM, CIP, TIFF,
ICON, MAGICK, DCM, MSL, WMF, MIFF, PCX, SUN, PSD, MVG, PWP, PICT, PDB,
SFW, or XCF files are processed.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"imagemagick", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-common", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imagemagick-doc", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagick++-dev", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagick++5", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore5", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmagickwand5", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perlmagick", ver:"6.7.7.10-5+deb7u16", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3559-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.703559");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2016-2805", "CVE-2016-2807", "CVE-2016-2808", "CVE-2016-2814");
  script_name("Debian Security Advisory DSA 3559-1 (iceweasel - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-04-27 00:00:00 +0200 (Wed, 27 Apr 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3559.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"iceweasel on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 38.8.0esr-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 38.8.0esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 45.1.0esr-1 of the firefox-esr source package and version
46.0-1 of the firefox source package.

We recommend that you upgrade your iceweasel packages.");
  script_tag(name:"summary", value:"Multiple security issues have been found
in Iceweasel, Debian's version of the Mozilla Firefox web browser: Multiple memory
safety errors and buffer overflows may lead to the execution of arbitrary code or
denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"iceweasel", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dev", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ak", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-csb", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ku", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lg", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nso", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ta-lk", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zu", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs17d", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs17d-dbg", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-17.0", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-17.0-dbg", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"38.8.0esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dev", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"38.8.0esr-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
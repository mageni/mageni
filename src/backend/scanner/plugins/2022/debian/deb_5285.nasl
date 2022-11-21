# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705285");
  script_version("2022-11-21T08:41:28+0000");
  script_cve_id("CVE-2021-37706", "CVE-2021-43299", "CVE-2021-43300", "CVE-2021-43301", "CVE-2021-43302", "CVE-2021-43303", "CVE-2021-43804", "CVE-2021-43845", "CVE-2021-46837", "CVE-2022-21722", "CVE-2022-21723", "CVE-2022-23608", "CVE-2022-24763", "CVE-2022-24764", "CVE-2022-24786", "CVE-2022-24792", "CVE-2022-24793", "CVE-2022-26498", "CVE-2022-26499", "CVE-2022-26651");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-11-21 08:41:28 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-03 23:20:00 +0000 (Mon, 03 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-11-19 02:00:03 +0000 (Sat, 19 Nov 2022)");
  script_name("Debian: Security Advisory for asterisk (DSA-5285-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5285.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5285-1");
  script_xref(name:"Advisory-ID", value:"DSA-5285-1");
  script_xref(name:"URL", value:"https://issues.asterisk.org/jira/browse/ASTERISK-29017");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'asterisk'
  package(s) announced via the DSA-5285-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been found in Asterisk, an Open Source
Private Branch Exchange. Buffer overflows and other programming errors could be
exploited for information disclosure or the execution of arbitrary code.

Special care should be taken when upgrading to this new upstream release.
Some configuration files and options have changed in order to remedy
certain security vulnerabilities. Most notably the pjsip TLS listener only
accepts TLSv1.3 connections in the default configuration now. This can be
reverted by adding method=tlsv1_2 to the transport in pjsip.conf. See also
[link moved to references].");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 1:16.28.0~dfsg-0+deb11u1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-tests", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-vpb", ver:"1:16.28.0~dfsg-0+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892729");
  script_version("2021-08-05T03:00:09+0000");
  script_cve_id("CVE-2021-32558");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-05 10:56:26 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-05 03:00:09 +0000 (Thu, 05 Aug 2021)");
  script_name("Debian LTS: Security Advisory for asterisk (DLA-2729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/08/msg00005.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2729-1");
  script_xref(name:"Advisory-ID", value:"DLA-2729-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/991710");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'asterisk'
  package(s) announced via the DLA-2729-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in the Asterisk telephony
system. If the IAX2 channel driver received a packet that contained
an unsupported media format, a crash could have occurred.

In addition, Asterisk are tracking this issue as 'AST-2021-008'.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this problem has been fixed in version
1:13.14.1~dfsg-2+deb9u5.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"asterisk-vpb", ver:"1:13.14.1~dfsg-2+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

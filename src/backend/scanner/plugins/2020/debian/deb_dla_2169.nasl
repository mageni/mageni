# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892169");
  script_version("2020-04-06T03:00:08+0000");
  script_cve_id("CVE-2017-9831", "CVE-2017-9832");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 03:00:08 +0000 (Mon, 06 Apr 2020)");
  script_name("Debian LTS: Security Advisory for libmtp (DLA-2169-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2169-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmtp'
  package(s) announced via the DLA-2169-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libmtp is a library for communicating with MTP aware devices. The Media
Transfer Protocol (commonly referred to as MTP) is a devised set of custom
extensions to support the transfer of music files on USB digital audio players
and movie files on USB portable media players.

CVE-2017-9831

An integer overflow vulnerability in the ptp_unpack_EOS_CustomFuncEx
function of the ptp-pack.c file allows attackers to cause a denial of
service (out-of-bounds memory access) or maybe remote code execution by
inserting a mobile device into a personal computer through a USB cable.

CVE-2017-9832

An integer overflow vulnerability in ptp-pack.c (ptp_unpack_OPL function)
allows attackers to cause a denial of service (out-of-bounds memory
access) or maybe remote code execution by inserting a mobile device into
a personal computer through a USB cable.");

  script_tag(name:"affected", value:"'libmtp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.1.8-1+deb8u1.

We recommend that you upgrade your libmtp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libmtp-common", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmtp-dbg", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmtp-dev", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmtp-doc", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmtp-runtime", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libmtp9", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtp-tools", ver:"1.1.8-1+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

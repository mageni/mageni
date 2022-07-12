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
  script_oid("1.3.6.1.4.1.25623.1.0.892677");
  script_version("2021-06-07T03:00:14+0000");
  script_cve_id("CVE-2018-25009", "CVE-2018-25010", "CVE-2018-25011", "CVE-2018-25012", "CVE-2018-25013", "CVE-2018-25014", "CVE-2020-36328", "CVE-2020-36329", "CVE-2020-36330", "CVE-2020-36331");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-07 10:15:34 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-07 03:00:14 +0000 (Mon, 07 Jun 2021)");
  script_name("Debian LTS: Security Advisory for libwebp (DLA-2677-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2677-1");
  script_xref(name:"Advisory-ID", value:"DLA-2677-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwebp'
  package(s) announced via the DLA-2677-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been discovered in libwebp

CVE-2018-25009

An out-of-bounds read was found in function WebPMuxCreateInternal.
The highest threat from this vulnerability is to data confidentiality
and to the service availability.

CVE-2018-25010

An out-of-bounds read was found in function ApplyFilter.
The highest threat from this vulnerability is to data confidentiality
and to the service availability.

CVE-2018-25011

A heap-based buffer overflow was found in PutLE16().
The highest threat from this vulnerability is to data confidentiality
and integrity as well as system availability.

CVE-2018-25012

An out-of-bounds read was found in function WebPMuxCreateInternal.
The highest threat from this vulnerability is to data confidentiality
and to the service availability.

CVE-2018-25013

An out-of-bounds read was found in function ShiftBytes.
The highest threat from this vulnerability is to data confidentiality
and to the service availability.

CVE-2018-25014

An uninitialized variable is used in function ReadSymbol.
The highest threat from this vulnerability is to data confidentiality
and integrity as well as system availability.

CVE-2020-36328

A heap-based buffer overflow in function WebPDecodeRGBInto is possible
due to an invalid check for buffer size. The highest threat from this
vulnerability is to data confidentiality and integrity as well as system
availability.

CVE-2020-36329

A use-after-free was found due to a thread being killed too early.
The highest threat from this vulnerability is to data confidentiality
and integrity as well as system availability.

CVE-2020-36330

An out-of-bounds read was found in function ChunkVerifyAndAssign.
The highest threat from this vulnerability is to data confidentiality
and to the service availability.

CVE-2020-36331

An out-of-bounds read was found in function ChunkAssignData.
The highest threat from this vulnerability is to data confidentiality
and to the service availability.");

  script_tag(name:"affected", value:"'libwebp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.5.2-1+deb9u1.

We recommend that you upgrade your libwebp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libwebp-dev", ver:"0.5.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebp6", ver:"0.5.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebpdemux2", ver:"0.5.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebpmux2", ver:"0.5.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"webp", ver:"0.5.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

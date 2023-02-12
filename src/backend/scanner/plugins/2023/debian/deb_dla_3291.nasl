# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893291");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2020-15256", "CVE-2021-23434", "CVE-2021-3805");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-04 13:29:00 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"creation_date", value:"2023-01-30 09:59:05 +0000 (Mon, 30 Jan 2023)");
  script_name("Debian LTS: Security Advisory for node-object-path (DLA-3291-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00031.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3291-1");
  script_xref(name:"Advisory-ID", value:"DLA-3291-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-object-path'
  package(s) announced via the DLA-3291-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that node-object-path, a Node.js module to access deep
object properties using dot-separated paths, was vulnerable to prototype
pollution.

CVE-2021-3805

Prototype pollution vulnerability in the `del()`, `empty()`,
`push()` and `insert()` functions when using the 'inherited props'
mode (e.g. when a new `object-path` instance is created with the
`includeInheritedProps` option set to `true` or when using the
`withInheritedProps` default instance).

CVE-2021-23434

A type confusion vulnerability can lead to a bypass of the
CVE-2020-15256 fix when the path components used in the path
parameter are arrays, because the === operator returns always false
when the type of the operands is different.");

  script_tag(name:"affected", value:"'node-object-path' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.11.4-2+deb10u2.

We recommend that you upgrade your node-object-path packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"node-object-path", ver:"0.11.4-2+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

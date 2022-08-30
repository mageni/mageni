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
  script_oid("1.3.6.1.4.1.25623.1.0.893084");
  script_version("2022-08-29T08:42:23+0000");
  script_cve_id("CVE-2020-15472", "CVE-2020-15476");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-29 08:42:23 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-06 19:21:00 +0000 (Mon, 06 Jul 2020)");
  script_tag(name:"creation_date", value:"2022-08-29 01:00:07 +0000 (Mon, 29 Aug 2022)");
  script_name("Debian LTS: Security Advisory for ndpi (DLA-3084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/08/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3084-1");
  script_xref(name:"Advisory-ID", value:"DLA-3084-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ndpi'
  package(s) announced via the DLA-3084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been discovered in ndpi: deep packet inspection
library.

CVE-2020-15472

H.323 dissector is vulnerable to a heap-based buffer over-read in ndpi_search_h323 in lib/protocols/h323.c.

CVE-2020-15476

Oracle protocol dissector has a heap-based buffer over-read in ndpi_search_oracle.");

  script_tag(name:"affected", value:"'ndpi' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.6-3+deb10u1.

We recommend that you upgrade your ndpi packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libndpi-bin", ver:"2.6-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libndpi-dev", ver:"2.6-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libndpi-wireshark", ver:"2.6-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libndpi2.6", ver:"2.6-3+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

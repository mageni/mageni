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
  script_oid("1.3.6.1.4.1.25623.1.0.893269");
  script_version("2023-01-16T10:11:20+0000");
  script_cve_id("CVE-2022-22728");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-16 10:11:20 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-15 02:00:04 +0000 (Sun, 15 Jan 2023)");
  script_name("Debian LTS: Security Advisory for libapreq2 (DLA-3269-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3269-1");
  script_xref(name:"Advisory-ID", value:"DLA-3269-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1018191");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libapreq2'
  package(s) announced via the DLA-3269-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in Apache libapreq2 versions 2.16 and earlier could cause a
buffer overflow while processing multipart form uploads. A remote
attacker could send a request causing a process crash which could lead
to a denial of service attack.");

  script_tag(name:"affected", value:"'libapreq2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
2.13-7~deb10u2.

We recommend that you upgrade your libapreq2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-apreq2", ver:"2.13-7~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-request-perl", ver:"2.13-7~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapreq2-3", ver:"2.13-7~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapreq2-dev", ver:"2.13-7~deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapreq2-doc", ver:"2.13-7~deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

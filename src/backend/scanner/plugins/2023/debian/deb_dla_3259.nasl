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
  script_oid("1.3.6.1.4.1.25623.1.0.893259");
  script_version("2023-01-10T10:12:01+0000");
  script_cve_id("CVE-2022-40150", "CVE-2022-45685", "CVE-2022-45693");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-01 02:00:46 +0000 (Sun, 01 Jan 2023)");
  script_name("Debian LTS: Security Advisory for libjettison-java (DLA-3259-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00045.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3259-1");
  script_xref(name:"Advisory-ID", value:"DLA-3259-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1022553");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjettison-java'
  package(s) announced via the DLA-3259-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws have been discovered in libjettison-java, a
collection of StAX parsers and writers for JSON. Specially crafted user input
may cause a denial of service via out-of-memory or stack overflow errors.

In addition a build failure related to the update was fixed in jersey1.");

  script_tag(name:"affected", value:"'libjettison-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.5.3-1~deb10u1.

We recommend that you upgrade your libjettison-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjettison-java", ver:"1.5.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

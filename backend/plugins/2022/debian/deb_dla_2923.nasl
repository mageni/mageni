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
  script_oid("1.3.6.1.4.1.25623.1.0.892923");
  script_version("2022-02-16T02:00:14+0000");
  script_cve_id("CVE-2021-42392", "CVE-2022-23221");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-16 11:08:17 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-16 02:00:14 +0000 (Wed, 16 Feb 2022)");
  script_name("Debian LTS: Security Advisory for h2database (DLA-2923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/02/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2923-1");
  script_xref(name:"Advisory-ID", value:"DLA-2923-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1003894");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'h2database'
  package(s) announced via the DLA-2923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security researchers of JFrog Security and Ismail Aydemir discovered two
remote code execution vulnerabilities in the H2 Java SQL database engine
which can be exploited through various attack vectors, most notably through
the H2 Console and by loading custom classes from remote servers through
JNDI. The H2 console is a developer tool and not required by any reverse-
dependency in Debian. It has been disabled in (old)stable releases.
Database developers are advised to use at least version 2.1.210-1, currently
available in Debian unstable.");

  script_tag(name:"affected", value:"'h2database' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.4.193-1+deb9u1.

We recommend that you upgrade your h2database packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libh2-java", ver:"1.4.193-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libh2-java-doc", ver:"1.4.193-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

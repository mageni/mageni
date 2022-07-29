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
  script_oid("1.3.6.1.4.1.25623.1.0.705190");
  script_version("2022-07-27T01:00:08+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-27 01:00:08 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-27 01:00:08 +0000 (Wed, 27 Jul 2022)");
  script_name("Debian: Security Advisory for spip (DSA-5190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5190.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5190-1");
  script_xref(name:"Advisory-ID", value:"DSA-5190-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip'
  package(s) announced via the DSA-5190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SPIP, a website engine for publishing, would allow
a malicious user to execute arbitrary code or escalate privileges.");

  script_tag(name:"affected", value:"'spip' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), this problem has been fixed
in version 3.2.4-1+deb10u9.

For the stable distribution (bullseye), this problem has been fixed in
version 3.2.11-3+deb11u5.

We recommend that you upgrade your spip packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.11-3+deb11u5", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.4-1+deb10u9", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

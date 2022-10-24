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
  script_oid("1.3.6.1.4.1.25623.1.0.705255");
  script_version("2022-10-19T01:00:10+0000");
  script_cve_id("CVE-2022-3515");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-19 01:00:10 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-19 01:00:10 +0000 (Wed, 19 Oct 2022)");
  script_name("Debian: Security Advisory for libksba (DSA-5255-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5255.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5255-1");
  script_xref(name:"Advisory-ID", value:"DSA-5255-1");
  script_xref(name:"URL", value:"https://gnupg.org/blog/20221017-pepe-left-the-ksba.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libksba'
  package(s) announced via the DSA-5255-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw was discovered in the CRL parser in libksba, an
X.509 and CMS support library, which could result in denial of service
or the execution of arbitrary code.

Details can be found in the upstream advisory at [link moved to references]");

  script_tag(name:"affected", value:"'libksba' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), this problem has been fixed in
version 1.5.0-3+deb11u1.

We recommend that you upgrade your libksba packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libksba-dev", ver:"1.5.0-3+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libksba-mingw-w64-dev", ver:"1.5.0-3+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libksba8", ver:"1.5.0-3+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

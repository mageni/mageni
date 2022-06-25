# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891916");
  script_version("2019-09-12T02:00:33+0000");
  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16424", "CVE-2018-16425", "CVE-2018-16426", "CVE-2018-16427", "CVE-2019-15945", "CVE-2019-15946");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-12 02:00:33 +0000 (Thu, 12 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-12 02:00:33 +0000 (Thu, 12 Sep 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1916-1] opensc security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1916-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/909444");
  script_xref(name:"URL", value:"https://bugs.debian.org/939668");
  script_xref(name:"URL", value:"https://bugs.debian.org/939669");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc'
  package(s) announced via the DSA-1916-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were fixed in opensc, a set of
libraries and utilities to access smart cards that support
cryptographic operations.

Out-of-bounds reads, buffer overflows and double frees could be used
by attackers able to supply crafted smart cards to cause a denial of
service (application crash) or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.16.0-3+deb8u1.

We recommend that you upgrade your opensc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.16.0-3+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.16.0-3+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
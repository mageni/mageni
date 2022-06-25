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
  script_oid("1.3.6.1.4.1.25623.1.0.892832");
  script_version("2021-11-30T02:00:13+0000");
  script_cve_id("CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-30 10:53:46 +0000 (Tue, 30 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-30 02:00:13 +0000 (Tue, 30 Nov 2021)");
  script_name("Debian LTS: Security Advisory for opensc (DLA-2832-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2832-1");
  script_xref(name:"Advisory-ID", value:"DLA-2832-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/939668");
  script_xref(name:"URL", value:"https://bugs.debian.org/939669");
  script_xref(name:"URL", value:"https://bugs.debian.org/947383");
  script_xref(name:"URL", value:"https://bugs.debian.org/972035");
  script_xref(name:"URL", value:"https://bugs.debian.org/972036");
  script_xref(name:"URL", value:"https://bugs.debian.org/972037");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc'
  package(s) announced via the DLA-2832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in the OpenSC smart card utilities.

CVE-2019-15945

Out-of-bounds access of an ASN.1 Bitstring.

CVE-2019-15946

Out-of-bounds access of an ASN.1 Octet string.

CVE-2019-19479

Incorrect read operation in the Setec driver.

CVE-2020-26570

Heap-based buffer overflow in the Oberthur driver.

CVE-2020-26571

Stack-based buffer overflow in the GPK driver.

CVE-2020-26572

Stack-based buffer overflow in the TCOS driver.");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.16.0-3+deb9u2.

We recommend that you upgrade your opensc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.16.0-3+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.16.0-3+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

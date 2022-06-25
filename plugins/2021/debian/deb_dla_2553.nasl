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
  script_oid("1.3.6.1.4.1.25623.1.0.892553");
  script_version("2021-02-10T04:00:23+0000");
  script_cve_id("CVE-2019-5086", "CVE-2019-5087");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-10 11:15:07 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-10 04:00:23 +0000 (Wed, 10 Feb 2021)");
  script_name("Debian LTS: Security Advisory for xcftools (DLA-2553-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00014.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2553-1");
  script_xref(name:"Advisory-ID", value:"DLA-2553-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/945317");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xcftools'
  package(s) announced via the DLA-2553-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Claudio Bozzato of Cisco Talos discovered an exploitable integer overflow
vulnerability in the flattenIncrementally function in the xcf2png and xcf2pnm
binaries of xcftools. An integer overflow can occur while walking through tiles
that could be exploited to corrupt memory and execute arbitrary code. In order
to trigger this vulnerability, a victim would need to open a specially crafted
XCF file.");

  script_tag(name:"affected", value:"'xcftools' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.0.7-6+deb9u1.

We recommend that you upgrade your xcftools packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"xcftools", ver:"1.0.7-6+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

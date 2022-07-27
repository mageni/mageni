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
  script_oid("1.3.6.1.4.1.25623.1.0.892645");
  script_version("2021-04-30T03:00:16+0000");
  script_cve_id("CVE-2019-0161", "CVE-2019-14558", "CVE-2019-14559", "CVE-2019-14562", "CVE-2019-14563", "CVE-2019-14575", "CVE-2019-14584", "CVE-2019-14586", "CVE-2019-14587", "CVE-2021-28210", "CVE-2021-28211");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-30 10:37:53 +0000 (Fri, 30 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-30 03:00:16 +0000 (Fri, 30 Apr 2021)");
  script_name("Debian LTS: Security Advisory for edk2 (DLA-2645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2645-1");
  script_xref(name:"Advisory-ID", value:"DLA-2645-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/952926");
  script_xref(name:"URL", value:"https://bugs.debian.org/968819");
  script_xref(name:"URL", value:"https://bugs.debian.org/952934");
  script_xref(name:"URL", value:"https://bugs.debian.org/977300");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2'
  package(s) announced via the DLA-2645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'edk2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0~20161202.7bbe0b3e-1+deb9u2.

We recommend that you upgrade your edk2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20161202.7bbe0b3e-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20161202.7bbe0b3e-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2020.2324");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-2324)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2324");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2324");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-latest-4.19' package(s) announced via the DLA-2324 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linux 4.19 has been packaged for Debian 9 as linux-4.19. This provides a supported upgrade path for systems that currently use kernel packages from the 'stretch-backports' suite.

However, 'apt full-upgrade' will *not* automatically install the updated kernel packages. You should explicitly install one of the following metapackages first, as appropriate for your system:

linux-image-4.19-686

linux-image-4.19-686-pae

linux-image-4.19-amd64

linux-image-4.19-arm64

linux-image-4.19-armmp

linux-image-4.19-armmp-lpae

linux-image-4.19-cloud-amd64

linux-image-4.19-marvell

linux-image-4.19-rpi

linux-image-4.19-rt-686-pae

linux-image-4.19-rt-amd64

linux-image-4.19-rt-arm64

linux-image-4.19-rt-armmp

For example, if the command 'uname -r' currently shows '4.19.0-0.bpo.9-amd64', you should install linux-image-4.19-amd64.

There is no need to upgrade systems using Linux 4.9, as that kernel version will also continue to be supported in the LTS period.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux-latest-4.19' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-686-pae", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-686", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-amd64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-arm64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-armmp-lpae", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-armmp", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-cloud-amd64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-marvell", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-rpi", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-rt-686-pae", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-rt-amd64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-rt-arm64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19-rt-armmp", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-686-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-686-pae-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-686-pae", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-686", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-amd64-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-amd64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-arm64-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-arm64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-armmp-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-armmp-lpae-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-armmp-lpae", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-armmp", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-cloud-amd64-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-cloud-amd64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-marvell-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-marvell", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rpi-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rpi", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-686-pae-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-686-pae", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-amd64-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-amd64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-arm64-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-arm64", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-armmp-dbg", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19-rt-armmp", ver:"4.19+105+deb10u5~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

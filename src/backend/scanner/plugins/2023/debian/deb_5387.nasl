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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5387");
  script_cve_id("CVE-2023-1668");
  script_tag(name:"creation_date", value:"2023-04-14 04:20:50 +0000 (Fri, 14 Apr 2023)");
  script_version("2023-04-14T10:10:02+0000");
  script_tag(name:"last_modification", value:"2023-04-14 10:10:02 +0000 (Fri, 14 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5387");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5387");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5387");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openvswitch");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openvswitch' package(s) announced via the DSA-5387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Marchard discovered that Open vSwitch, a software-based Ethernet virtual switch, is suspectible to denial of service via malformed IP packets.

For the stable distribution (bullseye), this problem has been fixed in version 2.15.0+ds1-2+deb11u4.

We recommend that you upgrade your openvswitch packages.

For the detailed security status of openvswitch please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dbg", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dev", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-ipsec", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-pki", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch-dpdk", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-testcontroller", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-vtep", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openvswitch", ver:"2.15.0+ds1-2+deb11u4", rls:"DEB11"))) {
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

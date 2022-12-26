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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5754.2");
  script_cve_id("CVE-2022-3524", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-43945");
  script_tag(name:"creation_date", value:"2022-12-13 04:10:37 +0000 (Tue, 13 Dec 2022)");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-20 12:49:00 +0000 (Thu, 20 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5754-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.10");

  script_xref(name:"Advisory-ID", value:"USN-5754-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5754-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-5754-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NFSD implementation in the Linux kernel did not
properly handle some RPC messages, leading to a buffer overflow. A remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-43945)

It was discovered that a memory leak existed in the IPv6 implementation of
the Linux kernel. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2022-3524)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-3564)

It was discovered that the ISDN implementation of the Linux kernel
contained a use-after-free vulnerability. A privileged user could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3565)

It was discovered that the TCP implementation in the Linux kernel contained
a data race condition. An attacker could possibly use this to cause
undesired behaviors. (CVE-2022-3566)

It was discovered that the IPv6 implementation in the Linux kernel
contained a data race condition. An attacker could possibly use this to
cause undesired behaviors. (CVE-2022-3567)

It was discovered that the Realtek RTL8152 USB Ethernet adapter driver in
the Linux kernel did not properly handle certain error conditions. A local
attacker with physical access could plug in a specially crafted USB device
to cause a denial of service (memory exhaustion). (CVE-2022-3594)

It was discovered that a null pointer dereference existed in the NILFS2
file system implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash). (CVE-2022-3621)");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 22.10.");

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

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1013-azure", ver:"5.19.0-1013.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.19.0.1013.10", rls:"UBUNTU22.10"))) {
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

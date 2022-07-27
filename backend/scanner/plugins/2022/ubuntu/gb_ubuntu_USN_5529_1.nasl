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
  script_oid("1.3.6.1.4.1.25623.1.0.845450");
  script_version("2022-07-22T12:12:01+0000");
  script_cve_id("CVE-2022-1679", "CVE-2022-1789", "CVE-2022-1852", "CVE-2022-1973", "CVE-2022-2078", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-34494", "CVE-2022-34495", "CVE-2022-1652");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-22 12:12:01 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-24 22:22:00 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2022-07-21 01:00:34 +0000 (Thu, 21 Jul 2022)");
  script_name("Ubuntu: Security Advisory for linux-oem-5.17 (USN-5529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5529-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-July/006688.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.17'
  package(s) announced via the USN-5529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Atheros ath9k wireless device driver in the
Linux kernel did not properly handle some error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-1679)

Yongkang Jia discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle guest TLB mapping invalidation requests in
some situations. An attacker in a guest VM could use this to cause a denial
of service (system crash) in the host OS. (CVE-2022-1789)

Qiuhao Li, Gaoning Pan, and Yongkang Jia discovered that the KVM hypervisor
implementation in the Linux kernel did not properly handle an illegal
instruction in a guest, resulting in a null pointer dereference. An
attacker in a guest VM could use this to cause a denial of service (system
crash) in the host OS. (CVE-2022-1852)

Gerald Lee discovered that the NTFS file system implementation in the Linux
kernel did not properly handle certain error conditions, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly expose sensitive information.
(CVE-2022-1973)

It was discovered that the netfilter subsystem in the Linux kernel
contained a buffer overflow in certain situations. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-2078)

It was discovered that some Intel processors did not completely perform
cleanup actions on multi-core shared buffers. A local attacker could
possibly use this to expose sensitive information. (CVE-2022-21123)

It was discovered that some Intel processors did not completely perform
cleanup actions on microarchitectural fill buffers. A local attacker could
possibly use this to expose sensitive information. (CVE-2022-21125)

It was discovered that some Intel processors did not properly perform
cleanup during specific special register write operations. A local attacker
could possibly use this to expose sensitive information. (CVE-2022-21166)

It was discovered that the virtio RPMSG bus driver in the Linux kernel
contained a double-free vulnerability in certain error conditions. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-34494, CVE-2022-34495)

Minh Yuan discovered that the floppy disk driver in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2022-1652)");

  script_tag(name:"affected", value:"'linux-oem-5.17' package(s) on Ubuntu 22.04 LTS.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.17.0-1013-oem", ver:"5.17.0-1013.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"5.17.0.1013.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"5.17.0.1013.12", rls:"UBUNTU22.04 LTS"))) {
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
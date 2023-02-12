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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5853.1");
  script_cve_id("CVE-2022-3628", "CVE-2022-3640", "CVE-2022-3649", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42895");
  script_tag(name:"creation_date", value:"2023-02-10 04:25:54 +0000 (Fri, 10 Feb 2023)");
  script_version("2023-02-10T04:25:54+0000");
  script_tag(name:"last_modification", value:"2023-02-10 04:25:54 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 18:50:00 +0000 (Mon, 24 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5853-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5853-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5853-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-azure-5.4, linux-gkeop, linux-kvm, linux-oracle, linux-raspi, linux-raspi-5.4' package(s) announced via the USN-5853-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux
kernel did not properly perform bounds checking in some situations. A
physically proximate attacker could use this to craft a malicious USB
device that when inserted, could cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-3628)

It was discovered that a use-after-free vulnerability existed in the
Bluetooth stack in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3640)

Khalid Masum discovered that the NILFS2 file system implementation in the
Linux kernel did not properly handle certain error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service or possibly execute arbitrary code. (CVE-2022-3649)

It was discovered that a race condition existed in the SMSC UFX USB driver
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-41849)

It was discovered that a race condition existed in the Roccat HID driver in
the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-41850)

Tamas Koczka discovered that the Bluetooth L2CAP implementation in the
Linux kernel did not properly initialize memory in some situations. A
physically proximate attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2022-42895)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-azure-5.4, linux-gkeop, linux-kvm, linux-oracle, linux-raspi, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1080-raspi", ver:"5.4.0-1080.91~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1103-azure", ver:"5.4.0-1103.109~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.4.0.1103.76", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1080.77", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1064-gkeop", ver:"5.4.0-1064.68", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1080-raspi", ver:"5.4.0-1080.91", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1086-kvm", ver:"5.4.0-1086.92", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1093-oracle", ver:"5.4.0-1093.102", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1096-aws", ver:"5.4.0-1096.104", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1103-azure", ver:"5.4.0-1103.109", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-139-generic-lpae", ver:"5.4.0-139.156", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-139-generic", ver:"5.4.0-139.156", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-139-lowlatency", ver:"5.4.0-139.156", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-20.04", ver:"5.4.0.1096.93", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-20.04", ver:"5.4.0.1103.96", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.4.0.139.137", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.4.0.139.137", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.4", ver:"5.4.0.1064.62", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.4.0.1064.62", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.4.0.1086.80", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.4.0.139.137", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.139.137", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.139.137", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-20.04", ver:"5.4.0.1093.86", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1080.110", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1080.110", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.4.0.139.137", rls:"UBUNTU20.04 LTS"))) {
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

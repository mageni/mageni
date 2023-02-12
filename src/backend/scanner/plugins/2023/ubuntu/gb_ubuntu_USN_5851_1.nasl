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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5851.1");
  script_cve_id("CVE-2022-3543", "CVE-2022-3619", "CVE-2022-3623", "CVE-2022-3628", "CVE-2022-3640", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42895", "CVE-2022-47940", "CVE-2023-0590");
  script_tag(name:"creation_date", value:"2023-02-10 04:25:54 +0000 (Fri, 10 Feb 2023)");
  script_version("2023-02-10T04:25:54+0000");
  script_tag(name:"last_modification", value:"2023-02-10 04:25:54 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 18:50:00 +0000 (Mon, 24 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5851-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5851-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5851-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-azure, linux-azure-5.15, linux-gkeop, linux-hwe-5.15, linux-ibm, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-oracle, linux-oracle-5.15, linux-raspi' package(s) announced via the USN-5851-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a memory leak existed in the Unix domain socket
implementation of the Linux kernel. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2022-3543)

It was discovered that the Bluetooth HCI implementation in the Linux kernel
did not properly deallocate memory in some situations. An attacker could
possibly use this cause a denial of service (memory exhaustion).
(CVE-2022-3619)

It was discovered that the hugetlb implementation in the Linux kernel
contained a race condition in some situations. A local attacker could use
this to cause a denial of service (system crash) or expose sensitive
information (kernel memory). (CVE-2022-3623)

It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux
kernel did not properly perform bounds checking in some situations. A
physically proximate attacker could use this to craft a malicious USB
device that when inserted, could cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-3628)

It was discovered that a use-after-free vulnerability existed in the
Bluetooth stack in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3640)

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
information (kernel memory). (CVE-2022-42895)

Arnaud Gatignol, Quentin Minster, Florent Saudel and Guillaume Teissier
discovered that the KSMBD implementation in the Linux kernel did not
properly validate user-supplied data in some situations. An authenticated
attacker could use this to cause a denial of service (system crash), expose
sensitive information (kernel memory) or possibly execute arbitrary code.
(CVE-2022-47940)

It was discovered that a race condition existed in the qdisc implementation
in the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0590)");

  script_tag(name:"affected", value:"'linux, linux-azure, linux-azure-5.15, linux-gkeop, linux-hwe-5.15, linux-ibm, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-oracle, linux-oracle-5.15, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1029-oracle", ver:"5.15.0-1029.35~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1033-azure", ver:"5.15.0-1033.40~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-generic-64k", ver:"5.15.0-60.66~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-generic-lpae", ver:"5.15.0-60.66~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-generic", ver:"5.15.0-60.66~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-lowlatency-64k", ver:"5.15.0-60.66~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-lowlatency", ver:"5.15.0-60.66~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.15.0.1033.40~20.04.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.60.66~20.04.26", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.60.66~20.04.26", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.60.66~20.04.26", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-20.04", ver:"5.15.0.60.66~20.04.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.15.0.60.66~20.04.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1029.35~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.60.66~20.04.26", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1015-gkeop", ver:"5.15.0-1015.19", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1024-raspi-nolpae", ver:"5.15.0-1024.26", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1024-raspi", ver:"5.15.0-1024.26", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1025-ibm", ver:"5.15.0-1025.28", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1028-kvm", ver:"5.15.0-1028.33", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1029-oracle", ver:"5.15.0-1029.35", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1033-azure", ver:"5.15.0-1033.40", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-generic-64k", ver:"5.15.0-60.66", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-generic-lpae", ver:"5.15.0-60.66", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-generic", ver:"5.15.0-60.66", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-lowlatency-64k", ver:"5.15.0-60.66", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-60-lowlatency", ver:"5.15.0-60.66", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-22.04", ver:"5.15.0.1033.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.15.0.1033.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-22.04", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1015.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1015.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1025.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.15.0.1028.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"5.15.0.60.53", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.15.0.60.53", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"5.15.0.60.53", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.15.0.60.53", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1029.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1024.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1024.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.15.0.60.58", rls:"UBUNTU22.04 LTS"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5814.1");
  script_cve_id("CVE-2022-3643", "CVE-2022-42896", "CVE-2022-4378", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2023-01-20 04:10:35 +0000 (Fri, 20 Jan 2023)");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-5814-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5814-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5814-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-gkeop, linux-intel-iotg, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-oracle-5.15' package(s) announced via the USN-5814-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kyle Zeng discovered that the sysctl implementation in the Linux kernel
contained a stack-based buffer overflow. A local attacker could use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-4378)

Tamas Koczka discovered that the Bluetooth L2CAP handshake implementation
in the Linux kernel contained multiple use-after-free vulnerabilities. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-42896)

It was discovered that the Xen netback driver in the Linux kernel did not
properly handle packets structured in certain ways. An attacker in a guest
VM could possibly use this to cause a denial of service (host NIC
availability). (CVE-2022-3643)

It was discovered that an integer overflow vulnerability existed in the
Bluetooth subsystem in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2022-45934)");

  script_tag(name:"affected", value:"'linux-azure, linux-gkeop, linux-intel-iotg, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-oracle-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1027-oracle", ver:"5.15.0-1027.33~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-58-lowlatency-64k", ver:"5.15.0-58.64~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-58-lowlatency", ver:"5.15.0-58.64~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-20.04", ver:"5.15.0.58.64~20.04.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.15.0.58.64~20.04.21", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1027.33~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1013-gkeop", ver:"5.15.0-1013.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1023-intel-iotg", ver:"5.15.0-1023.28", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-58-lowlatency-64k", ver:"5.15.0-58.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-58-lowlatency", ver:"5.15.0-58.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1013.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1013.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1023.22", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"5.15.0.58.51", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.15.0.58.51", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"5.15.0.58.51", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.15.0.58.51", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1015-lowlatency-64k", ver:"5.19.0-1015.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1015-lowlatency", ver:"5.19.0-1015.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1017-azure", ver:"5.19.0-1017.18", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.19.0.1017.13", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.19.0.1015.12", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.19.0.1015.12", rls:"UBUNTU22.10"))) {
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

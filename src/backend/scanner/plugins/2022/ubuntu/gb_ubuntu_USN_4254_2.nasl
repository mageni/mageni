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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2020.4254.2");
  script_cve_id("CVE-2019-14615", "CVE-2019-15291", "CVE-2019-18683", "CVE-2019-18885", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19227", "CVE-2019-19332");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-05 05:15:00 +0000 (Thu, 05 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-4254-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4254-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4254-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial' package(s) announced via the USN-4254-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4254-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 ESM.

It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors. A
local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that a race condition existed in the Virtual Video Test
Driver in the Linux kernel. An attacker with write access to /dev/video0 on
a system with the vivid module loaded could possibly use this to gain
administrative privileges. (CVE-2019-18683)

It was discovered that the btrfs file system in the Linux kernel did not
properly validate metadata, leading to a NULL pointer dereference. An
attacker could use this to specially craft a file system image that, when
mounted, could cause a denial of service (system crash). (CVE-2019-18885)

It was discovered that multiple memory leaks existed in the Marvell WiFi-Ex
Driver for the Linux kernel. A local attacker could possibly use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-19057)

It was discovered that the crypto subsystem in the Linux kernel did not
properly deallocate memory in certain error conditions. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19062)

It was discovered that the Realtek rtlwifi USB device driver in the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19063)

Dan Carpenter discovered that the AppleTalk networking subsystem of the
Linux kernel did not properly handle certain error conditions, leading to a
NULL pointer dereference. A local attacker could use this to cause a denial
of service (system crash). (CVE-2019-19227)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle ioctl requests to get emulated CPUID
features. An attacker with access to /dev/kvm could use this to cause a
denial of service (system crash). (CVE-2019-19332)

It was discovered that the B2C2 FlexCop USB device driver in the Linux
kernel did not properly validate device metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-15291)");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1061-aws", ver:"4.4.0-1061.65", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-generic-lpae", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-generic", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-lowlatency", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-powerpc-e500mc", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-powerpc-smp", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-powerpc64-emb", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-173-powerpc64-smp", ver:"4.4.0-173.203~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1061.62", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.173.152", rls:"UBUNTU14.04 LTS"))) {
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

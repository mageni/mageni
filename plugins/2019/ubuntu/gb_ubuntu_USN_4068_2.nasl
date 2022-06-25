# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.844103");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2019-11085", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-24 02:01:30 +0000 (Wed, 24 Jul 2019)");
  script_name("Ubuntu Update for linux-gcp USN-4068-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-July/005026.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp'
  package(s) announced via the USN-4068-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4068-1 fixed vulnerabilities in the Linux kernel for Ubuntu
18.04 LTS. This update provides the corresponding updates for the
Linux Hardware Enablement (HWE) kernel from Ubuntu 18.04 for Ubuntu
16.04 LTS.

Adam Zabrocki discovered that the Intel i915 kernel mode graphics driver in
the Linux kernel did not properly restrict mmap() ranges in some
situations. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-11085)

It was discovered that a race condition leading to a use-after-free existed
in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux
kernel. The RDS protocol is blacklisted by default in Ubuntu. If enabled, a
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-11815)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly zero out memory in some situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2019-11833)

It was discovered that the Bluetooth Human Interface Device Protocol (HIDP)
implementation in the Linux kernel did not properly verify strings were
NULL terminated in certain situations. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2019-11884)");

  script_tag(name:"affected", value:"'linux-gcp' package(s) on Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1037-gcp", ver:"4.15.0-1037.39~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-55-generic", ver:"4.15.0-55.60~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-55-generic-lpae", ver:"4.15.0-55.60~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-55-lowlatency", ver:"4.15.0-55.60~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1037.51", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.55.76", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.15.0.55.76", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1037.51", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.55.76", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.55.76", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.55.76", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
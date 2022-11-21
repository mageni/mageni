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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5729.2");
  script_cve_id("CVE-2022-20422", "CVE-2022-2905", "CVE-2022-2978", "CVE-2022-3028", "CVE-2022-3625", "CVE-2022-3635", "CVE-2022-39190", "CVE-2022-40768");
  script_tag(name:"creation_date", value:"2022-11-21 04:15:13 +0000 (Mon, 21 Nov 2022)");
  script_version("2022-11-21T04:15:13+0000");
  script_tag(name:"last_modification", value:"2022-11-21 04:15:13 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 17:57:00 +0000 (Mon, 24 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5729-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5729-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5729-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp-5.15, linux-gke-5.15, linux-intel-iotg, linux-raspi' package(s) announced via the USN-5729-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the instruction emulator
of the Linux kernel on Arm 64-bit systems. A local attacker could use this
to cause a denial of service (system crash). (CVE-2022-20422)

Hsin-Wei Hung discovered that the BPF subsystem in the Linux kernel
contained an out-of-bounds read vulnerability in the x86 JIT compiler. A
local attacker could possibly use this to cause a denial of service (system
crash) or expose sensitive information (kernel memory). (CVE-2022-2905)

Hao Sun and Jiacheng Xu discovered that the NILFS file system
implementation in the Linux kernel contained a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-2978)

Abhishek Shah discovered a race condition in the PF_KEYv2 implementation in
the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly expose sensitive information (kernel
memory). (CVE-2022-3028)

It was discovered that the Netlink device interface implementation in the
Linux kernel did not properly handle certain error conditions, leading to a
use-after-free vulnerability with some network device drivers. A local
attacker with admin access to the network device could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-3625)

It was discovered that the IDT 77252 ATM PCI device driver in the Linux
kernel did not properly remove any pending timers during device exit,
resulting in a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2022-3635)

Gwangun Jung discovered that the netfilter subsystem in the Linux kernel
did not properly prevent binding to an already bound chain. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-39190)

Xingyuan Mo and Gengjia Chen discovered that the Promise SuperTrak EX
storage controller driver in the Linux kernel did not properly handle
certain structures. A local attacker could potentially use this to expose
sensitive information (kernel memory). (CVE-2022-40768)");

  script_tag(name:"affected", value:"'linux-gcp-5.15, linux-gke-5.15, linux-intel-iotg, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1020-gke", ver:"5.15.0-1020.25~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1022-gcp", ver:"5.15.0-1022.29~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.15.0.1022.29~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1020.25~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1018-intel-iotg", ver:"5.15.0-1018.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1018-raspi-nolpae", ver:"5.15.0-1018.20", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1018-raspi", ver:"5.15.0-1018.20", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1018.19", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1018.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1018.17", rls:"UBUNTU22.04 LTS"))) {
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

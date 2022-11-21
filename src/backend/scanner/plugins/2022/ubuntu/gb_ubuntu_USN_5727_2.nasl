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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5727.2");
  script_cve_id("CVE-2022-20422", "CVE-2022-2153", "CVE-2022-2978", "CVE-2022-3028", "CVE-2022-3635", "CVE-2022-36879", "CVE-2022-40768");
  script_tag(name:"creation_date", value:"2022-11-21 04:15:13 +0000 (Mon, 21 Nov 2022)");
  script_version("2022-11-21T04:15:13+0000");
  script_tag(name:"last_modification", value:"2022-11-21 04:15:13 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-30 19:19:00 +0000 (Tue, 30 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5727-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5727-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5727-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-gcp-4.15' package(s) announced via the USN-5727-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the instruction emulator
of the Linux kernel on Arm 64-bit systems. A local attacker could use this
to cause a denial of service (system crash). (CVE-2022-20422)

It was discovered that the KVM implementation in the Linux kernel did not
properly handle virtual CPUs without APICs in certain situations. A local
attacker could possibly use this to cause a denial of service (host system
crash). (CVE-2022-2153)

Hao Sun and Jiacheng Xu discovered that the NILFS file system
implementation in the Linux kernel contained a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-2978)

Abhishek Shah discovered a race condition in the PF_KEYv2 implementation in
the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly expose sensitive information (kernel
memory). (CVE-2022-3028)

It was discovered that the IDT 77252 ATM PCI device driver in the Linux
kernel did not properly remove any pending timers during device exit,
resulting in a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2022-3635)

It was discovered that the Netlink Transformation (XFRM) subsystem in the
Linux kernel contained a reference counting error. A local attacker could
use this to cause a denial of service (system crash). (CVE-2022-36879)

Xingyuan Mo and Gengjia Chen discovered that the Promise SuperTrak EX
storage controller driver in the Linux kernel did not properly handle
certain structures. A local attacker could potentially use this to expose
sensitive information (kernel memory). (CVE-2022-40768)");

  script_tag(name:"affected", value:"'linux-gcp, linux-gcp-4.15' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1138-gcp", ver:"4.15.0-1138.154~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1138.132", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1138.132", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1138-gcp", ver:"4.15.0-1138.154", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1138.154", rls:"UBUNTU18.04 LTS"))) {
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

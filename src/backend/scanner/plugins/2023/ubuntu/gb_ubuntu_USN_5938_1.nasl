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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5938.1");
  script_cve_id("CVE-2022-3169", "CVE-2022-3344", "CVE-2022-3435", "CVE-2022-3521", "CVE-2022-3545", "CVE-2022-4139", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4379", "CVE-2022-45869", "CVE-2022-47518", "CVE-2022-47519", "CVE-2022-47520", "CVE-2022-47521", "CVE-2023-0179", "CVE-2023-0461", "CVE-2023-0468");
  script_tag(name:"creation_date", value:"2023-03-09 04:11:27 +0000 (Thu, 09 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-22 16:15:00 +0000 (Thu, 22 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-5938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5938-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5938-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gkeop' package(s) announced via the USN-5938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Upper Level Protocol (ULP) subsystem in the
Linux kernel did not properly handle sockets entering the LISTEN state in
certain protocols, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0461)

Davide Ornaghi discovered that the netfilter subsystem in the Linux kernel
did not properly handle VLAN headers in some situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-0179)

It was discovered that the NVMe driver in the Linux kernel did not properly
handle reset events in some situations. A local attacker could use this to
cause a denial of service (system crash). (CVE-2022-3169)

Maxim Levitsky discovered that the KVM nested virtualization (SVM)
implementation for AMD processors in the Linux kernel did not properly
handle nested shutdown execution. An attacker in a guest vm could use this
to cause a denial of service (host kernel crash) (CVE-2022-3344)

Gwangun Jung discovered a race condition in the IPv4 implementation in the
Linux kernel when deleting multipath routes, resulting in an out-of-bounds
read. An attacker could use this to cause a denial of service (system
crash) or possibly expose sensitive information (kernel memory).
(CVE-2022-3435)

It was discovered that a race condition existed in the Kernel Connection
Multiplexor (KCM) socket implementation in the Linux kernel when releasing
sockets in certain situations. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-3521)

It was discovered that the Netronome Ethernet driver in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3545)

It was discovered that the Intel i915 graphics driver in the Linux kernel
did not perform a GPU TLB flush in some situations. A local attacker could
use this to cause a denial of service or possibly execute arbitrary code.
(CVE-2022-4139)

It was discovered that a race condition existed in the Xen network backend
driver in the Linux kernel when handling dropped packets in certain
circumstances. An attacker could use this to cause a denial of service
(kernel deadlock). (CVE-2022-42328, CVE-2022-42329)

It was discovered that the NFSD implementation in the Linux kernel
contained a use-after-free vulnerability. A remote attacker could possibly
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2022-4379)

It was discovered that a race condition existed in the x86 KVM subsystem
implementation in the Linux kernel when nested virtualization and the TDP
MMU are enabled. An attacker in a guest vm could use this to cause a denial
of service (host OS crash). (CVE-2022-45869)

It ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gkeop' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1016-gkeop", ver:"5.15.0-1016.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1016.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1016.15", rls:"UBUNTU22.04 LTS"))) {
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

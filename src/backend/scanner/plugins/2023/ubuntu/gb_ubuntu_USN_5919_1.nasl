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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5919.1");
  script_cve_id("CVE-2022-3521", "CVE-2022-3545", "CVE-2022-3628", "CVE-2022-3640", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-42895", "CVE-2022-43750", "CVE-2022-4378", "CVE-2023-0461");
  script_tag(name:"creation_date", value:"2023-03-06 04:11:16 +0000 (Mon, 06 Mar 2023)");
  script_version("2023-03-06T10:10:02+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:02 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 18:50:00 +0000 (Mon, 24 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5919-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5919-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5919-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-hwe, linux-oracle' package(s) announced via the USN-5919-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Upper Level Protocol (ULP) subsystem in the
Linux kernel did not properly handle sockets entering the LISTEN state in
certain protocols, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0461)

Kyle Zeng discovered that the sysctl implementation in the Linux kernel
contained a stack-based buffer overflow. A local attacker could use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-4378)

It was discovered that a race condition existed in the Kernel Connection
Multiplexor (KCM) socket implementation in the Linux kernel when releasing
sockets in certain situations. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-3521)

It was discovered that the Netronome Ethernet driver in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3545)

It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux
kernel did not properly perform bounds checking in some situations. A
physically proximate attacker could use this to craft a malicious USB
device that when inserted, could cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-3628)

It was discovered that a use-after-free vulnerability existed in the
Bluetooth stack in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3640)

It was discovered that the NILFS2 file system implementation in the Linux
kernel did not properly deallocate memory in certain error conditions. An
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2022-3646)

Khalid Masum discovered that the NILFS2 file system implementation in the
Linux kernel did not properly handle certain error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service or possibly execute arbitrary code. (CVE-2022-3649)

It was discovered that a race condition existed in the Xen network backend
driver in the Linux kernel when handling dropped packets in certain
circumstances. An attacker could use this to cause a denial of service
(kernel deadlock). (CVE-2022-42328, CVE-2022-42329)

Tamas Koczka discovered that the Bluetooth L2CAP implementation in the
Linux kernel did not properly initialize memory in some situations. A
physically proximate attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2022-42895)

It was discovered that the USB monitoring (usbmon) component in the Linux
kernel did not properly set permissions on memory mapped in to user space
processes. A local attacker could use this to cause ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws-hwe, linux-oracle' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1115-oracle", ver:"4.15.0-1115.126~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1151-aws", ver:"4.15.0-1151.164~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1151.134", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1115.96", rls:"UBUNTU16.04 LTS"))) {
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

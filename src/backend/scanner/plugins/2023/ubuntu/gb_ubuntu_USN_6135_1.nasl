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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6135.1");
  script_cve_id("CVE-2023-1380", "CVE-2023-2612", "CVE-2023-30456", "CVE-2023-31436", "CVE-2023-32233");
  script_tag(name:"creation_date", value:"2023-06-05 04:09:34 +0000 (Mon, 05 Jun 2023)");
  script_version("2023-06-05T09:09:07+0000");
  script_tag(name:"last_modification", value:"2023-06-05 09:09:07 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 21:15:00 +0000 (Mon, 15 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6135-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6135-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6135-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-fde, linux-azure-fde-5.15' package(s) announced via the USN-6135-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Patryk Sondej and Piotr Krysiuk discovered that a race condition existed in
the netfilter subsystem of the Linux kernel when processing batch requests,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-32233)

Gwangun Jung discovered that the Quick Fair Queueing scheduler
implementation in the Linux kernel contained an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-31436)

Reima Ishii discovered that the nested KVM implementation for Intel x86
processors in the Linux kernel did not properly validate control registers
in certain situations. An attacker in a guest VM could use this to cause a
denial of service (guest crash). (CVE-2023-30456)

It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux
kernel did not properly perform data buffer size validation in some
situations. A physically proximate attacker could use this to craft a
malicious USB device that when inserted, could cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-1380)

Jean-Baptiste Cayrou discovered that the shiftfs file system in the Ubuntu
Linux kernel contained a race condition when handling inode locking in some
situations. A local attacker could use this to cause a denial of service
(kernel deadlock). (CVE-2023-2612)");

  script_tag(name:"affected", value:"'linux-azure-fde, linux-azure-fde-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1039-azure-fde", ver:"5.15.0-1039.46~20.04.1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.15.0.1039.46~20.04.1.18", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1039-azure-fde", ver:"5.15.0-1039.46.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.15.0.1039.46.16", rls:"UBUNTU22.04 LTS"))) {
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

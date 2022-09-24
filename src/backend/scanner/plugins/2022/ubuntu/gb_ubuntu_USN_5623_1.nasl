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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5623.1");
  script_cve_id("CVE-2021-33061", "CVE-2021-33655", "CVE-2022-1012", "CVE-2022-1729", "CVE-2022-1852", "CVE-2022-1943", "CVE-2022-1973", "CVE-2022-2318", "CVE-2022-2503", "CVE-2022-26365", "CVE-2022-2873", "CVE-2022-2959", "CVE-2022-32296", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34494", "CVE-2022-34495", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-09-22 04:39:28 +0000 (Thu, 22 Sep 2022)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 13:36:00 +0000 (Thu, 11 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5623-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5623-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe-5.15, linux-lowlatency-hwe-5.15' package(s) announced via the USN-5623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asaf Modelevsky discovered that the Intel(R) 10GbE PCI Express (ixgbe)
Ethernet driver for the Linux kernel performed insufficient control flow
management. A local attacker could possibly use this to cause a denial of
service. (CVE-2021-33061)

It was discovered that the framebuffer driver on the Linux kernel did not
verify size limits when changing font or screen size, leading to an out-of-
bounds write. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-33655)

Moshe Kol, Amit Klein and Yossi Gilad discovered that the IP implementation
in the Linux kernel did not provide sufficient randomization when
calculating port offsets. An attacker could possibly use this to expose
sensitive information. (CVE-2022-1012, CVE-2022-32296)

Norbert Slusarek discovered that a race condition existed in the perf
subsystem in the Linux kernel, resulting in a use-after-free vulnerability.
A privileged local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-1729)

Qiuhao Li, Gaoning Pan, and Yongkang Jia discovered that the KVM hypervisor
implementation in the Linux kernel did not properly handle an illegal
instruction in a guest, resulting in a null pointer dereference. An
attacker in a guest VM could use this to cause a denial of service (system
crash) in the host OS. (CVE-2022-1852)

It was discovered that the UDF file system implementation in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-1943)

Gerald Lee discovered that the NTFS file system implementation in the Linux
kernel did not properly handle certain error conditions, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly expose sensitive information.
(CVE-2022-1973)

Duoming Zhou discovered that race conditions existed in the timer handling
implementation of the Linux kernel's Rose X.25 protocol layer, resulting in
use-after-free vulnerabilities. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-2318)

It was discovered that the device-mapper verity (dm-verity) driver in the
Linux kernel did not properly verify targets being loaded into the device-
mapper table. A privileged attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2022-2503)

Roger Pau Monne discovered that the Xen virtual block driver in the Linux
kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-26365)

Zheyu Ma discovered that the Intel iSMT SMBus host controller driver in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-hwe-5.15, linux-lowlatency-hwe-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-48-generic-64k", ver:"5.15.0-48.54~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-48-generic-lpae", ver:"5.15.0-48.54~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-48-generic", ver:"5.15.0-48.54~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-48-lowlatency-64k", ver:"5.15.0-48.54~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-48-lowlatency", ver:"5.15.0-48.54~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.48.54~20.04.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.48.54~20.04.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.48.54~20.04.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-20.04", ver:"5.15.0.48.54~20.04.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.15.0.48.54~20.04.16", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.48.54~20.04.18", rls:"UBUNTU20.04 LTS"))) {
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

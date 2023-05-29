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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6096.1");
  script_cve_id("CVE-2022-27672", "CVE-2022-36280", "CVE-2022-3707", "CVE-2022-4129", "CVE-2022-4842", "CVE-2022-48423", "CVE-2022-48424", "CVE-2023-0210", "CVE-2023-0394", "CVE-2023-0458", "CVE-2023-0459", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1075", "CVE-2023-1078", "CVE-2023-1118", "CVE-2023-1513", "CVE-2023-1652", "CVE-2023-21102", "CVE-2023-21106", "CVE-2023-2162", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-26544", "CVE-2023-32269");
  script_tag(name:"creation_date", value:"2023-05-23 04:09:14 +0000 (Tue, 23 May 2023)");
  script_version("2023-05-23T11:14:48+0000");
  script_tag(name:"last_modification", value:"2023-05-23 11:14:48 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 19:25:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6096-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6096-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-hwe-5.19' package(s) announced via the USN-6096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that some AMD x86-64 processors with SMT enabled could
speculatively execute instructions using a return address from a sibling
thread. A local attacker could possibly use this to expose sensitive
information. (CVE-2022-27672)

Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2022-36280)

Zheng Wang discovered that the Intel i915 graphics driver in the Linux
kernel did not properly handle certain error conditions, leading to a
double-free. A local attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-3707)

Haowei Yan discovered that a race condition existed in the Layer 2
Tunneling Protocol (L2TP) implementation in the Linux kernel. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-4129)

It was discovered that the NTFS file system implementation in the Linux
kernel contained a null pointer dereference in some situations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-4842)

It was discovered that the NTFS file system implementation in the Linux
kernel did not properly validate attributes in certain situations, leading
to an out-of-bounds write vulnerability. A local attacker could use this to
cause a denial of service (system crash). (CVE-2022-48423)

It was discovered that the NTFS file system implementation in the Linux
kernel did not properly validate attributes in certain situations, leading
to an out-of-bounds read vulnerability. A local attacker could possibly use
this to expose sensitive information (kernel memory). (CVE-2022-48424)

It was discovered that the KSMBD implementation in the Linux kernel did not
properly validate buffer lengths, leading to a heap-based buffer overflow.
A remote attacker could possibly use this to cause a denial of service
(system crash). (CVE-2023-0210)

Kyle Zeng discovered that the IPv6 implementation in the Linux kernel
contained a NULL pointer dereference vulnerability in certain situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-0394)

Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the
do_prlimit() function in the Linux kernel did not properly handle
speculative execution barriers. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2023-0458)

Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did
not properly implement speculative execution barriers in usercopy functions
in certain situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-0459)

It was discovered that the Human Interface Device (HID) support driver in
the Linux kernel contained a type confusion ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gcp, linux-hwe-5.19' package(s) on Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-42-generic-64k", ver:"5.19.0-42.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-42-generic-lpae", ver:"5.19.0-42.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-42-generic", ver:"5.19.0-42.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"5.19.0.42.43~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"5.19.0.42.43~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-22.04", ver:"5.19.0.42.43~22.04.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"5.19.0.42.43~22.04.15", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1024-gcp", ver:"5.19.0-1024.26", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.19.0.1024.20", rls:"UBUNTU22.10"))) {
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

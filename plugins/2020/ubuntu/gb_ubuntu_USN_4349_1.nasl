# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844417");
  script_version("2020-05-07T07:41:43+0000");
  script_cve_id("CVE-2018-12178", "CVE-2018-12180", "CVE-2018-12181", "CVE-2019-14558", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575", "CVE-2019-14586", "CVE-2019-14587");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-07 10:48:07 +0000 (Thu, 07 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-01 03:00:46 +0000 (Fri, 01 May 2020)");
  script_name("Ubuntu: Security Advisory for edk2 (USN-4349-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU19\.10|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-April/005417.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2'
  package(s) announced via the USN-4349-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in the network stack. An unprivileged user
could potentially enable escalation of privilege and/or denial of service.
This issue was already fixed in a previous release for 18.04 LTS and 19.10.
(CVE-2018-12178)

A buffer overflow was discovered in BlockIo service. An unauthenticated user
could potentially enable escalation of privilege, information disclosure and/or
denial of service. This issue was already fixed in a previous release for 18.04
LTS and 19.10. (CVE-2018-12180)

A stack overflow was discovered in bmp. An unprivileged user
could potentially enable denial of service or elevation of privilege via
local access. This issue was already fixed in a previous release for 18.04
LTS and 19.10. (CVE-2018-12181)

It was discovered that memory was not cleared before free that could lead
to potential password leak. (CVE-2019-14558)

A memory leak was discovered in ArpOnFrameRcvdDpc. An attacker could
possibly use this issue to cause a denial of service or other unspecified
impact. (CVE-2019-14559)

An integer overflow was discovered in MdeModulePkg/PiDxeS3BootScriptLib.
An attacker could possibly use this issue to cause a denial of service or
other unspecified impact. (CVE-2019-14563)

It was discovered that the affected version doesn't properly check whether an
unsigned EFI file should be allowed or not. An attacker could possibly load
unsafe content by bypassing the verification. (CVE-2019-14575)

It was discovered that original configuration runtime memory is freed, but it
is still exposed to the OS runtime. (CVE-2019-14586)

A double-unmap was discovered in TRB creation. An attacker could use it to
cause a denial of service or other unspecified impact. (CVE-2019-14587)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20190606.20d2e5a1-2ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20190606.20d2e5a1-2ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20190606.20d2e5a1-2ubuntu1.1", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20180205.c0d9813c-2ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20180205.c0d9813c-2ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20180205.c0d9813c-2ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20160408.ffea0a2c-2ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20160408.ffea0a2c-2ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
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
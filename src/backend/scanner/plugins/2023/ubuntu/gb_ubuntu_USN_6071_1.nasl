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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6071.1");
  script_cve_id("CVE-2022-2590", "CVE-2022-3303", "CVE-2022-3586", "CVE-2022-40307", "CVE-2022-4095", "CVE-2022-4662", "CVE-2023-0386", "CVE-2023-0468", "CVE-2023-1829", "CVE-2023-1859", "CVE-2023-23455", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2023-05-11 04:09:44 +0000 (Thu, 11 May 2023)");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 19:16:00 +0000 (Wed, 19 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-6071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6071-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6071-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.17' package(s) announced via the USN-6071-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Traffic-Control Index (TCINDEX) implementation
in the Linux kernel did not properly perform filter deactivation in some
situations. A local attacker could possibly use this to gain elevated
privileges. Please note that with the fix for this CVE, kernel support for
the TCINDEX classifier has been removed. (CVE-2023-1829)

Lin Ma discovered a race condition in the io_uring subsystem in the Linux
kernel, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-0468)

It was discovered that the OverlayFS implementation in the Linux kernel did
not properly handle copy up operation in some conditions. A local attacker
could possibly use this to gain elevated privileges. (CVE-2023-0386)

David Hildenbrand discovered that a race condition existed in the memory
manager of the Linux kernel when handling copy-on-write with shared memory
pages. A local attacker could use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2022-2590)

It was discovered that the sound subsystem in the Linux kernel contained a
race condition in some situations. A local attacker could use this to cause
a denial of service (system crash). (CVE-2022-3303)

Gwnaun Jung discovered that the SFB packet scheduling implementation in the
Linux kernel contained a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-3586)

It was discovered that a race condition existed in the EFI capsule loader
driver in the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-40307)

Zheng Wang and Zhuorao Yang discovered that the RealTek RTL8712U wireless
driver in the Linux kernel contained a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-4095)

It was discovered that the USB core subsystem in the Linux kernel did not
properly handle nested reset events. A local attacker with physical access
could plug in a specially crafted USB device to cause a denial of service
(kernel deadlock). (CVE-2022-4662)

It was discovered that a race condition existed in the Xen transport layer
implementation for the 9P file system protocol in the Linux kernel, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (guest crash) or expose sensitive information (guest
kernel memory). (CVE-2023-1859)

Kyle Zeng discovered that the ATM VC queuing discipline implementation in
the Linux kernel contained a type confusion vulnerability in some
situations. An attacker could use this to cause a denial of service (system
crash). ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-5.17' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.17.0-1031-oem", ver:"5.17.0-1031.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"5.17.0.1031.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"5.17.0.1031.29", rls:"UBUNTU22.04 LTS"))) {
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

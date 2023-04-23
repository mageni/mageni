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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6033.1");
  script_cve_id("CVE-2022-4269", "CVE-2023-1032", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1079", "CVE-2023-1118", "CVE-2023-1583", "CVE-2023-1670", "CVE-2023-1829", "CVE-2023-1855", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-25012", "CVE-2023-28466", "CVE-2023-28866", "CVE-2023-30456");
  script_tag(name:"creation_date", value:"2023-04-20 04:09:21 +0000 (Thu, 20 Apr 2023)");
  script_version("2023-04-20T10:42:24+0000");
  script_tag(name:"last_modification", value:"2023-04-20 10:42:24 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-13 20:10:00 +0000 (Thu, 13 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-6033-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6033-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6033-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.1' package(s) announced via the USN-6033-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Traffic-Control Index (TCINDEX) implementation
in the Linux kernel did not properly perform filter deactivation in some
situations. A local attacker could possibly use this to gain elevated
privileges. Please note that with the fix for this CVE, kernel support for
the TCINDEX classifier has been removed. (CVE-2023-1829)

William Zhao discovered that the Traffic Control (TC) subsystem in the
Linux kernel did not properly handle network packet retransmission in
certain situations. A local attacker could use this to cause a denial of
service (kernel deadlock). (CVE-2022-4269)

Thadeu Cascardo discovered that the io_uring subsystem contained a double-
free vulnerability in certain memory allocation error conditions. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2023-1032)

It was discovered that the TUN/TAP driver in the Linux kernel did not
properly initialize socket data. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-1076)

It was discovered that the Real-Time Scheduling Class implementation in the
Linux kernel contained a type confusion vulnerability in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-1077)

It was discovered that the ASUS HID driver in the Linux kernel did not
properly handle device removal, leading to a use-after-free vulnerability.
A local attacker with physical access could plug in a specially crafted USB
device to cause a denial of service (system crash). (CVE-2023-1079)

It was discovered that the io_uring subsystem in the Linux kernel did not
properly perform file table updates in some situations, leading to a null
pointer dereference vulnerability. A local attacker could use this to cause
a denial of service (system crash). (CVE-2023-1583)

It was discovered that the Xircom PCMCIA network device driver in the Linux
kernel did not properly handle device removal events. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2023-1670)

It was discovered that the APM X-Gene SoC hardware monitoring driver in the
Linux kernel contained a race condition, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or expose sensitive information (kernel memory).
(CVE-2023-1855)

It was discovered that a race condition existed in the Bluetooth HCI SDIO
driver, leading to a use-after-free vulnerability. A local attacker could
use this to cause a denial of service (system crash). (CVE-2023-1989)

It was discovered that the ST NCI NFC driver did not properly handle device
removal events. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2023-1990)

Jose Oliveira and Rodrigo Branco discovered that the Spectre Variant 2
mitigations with prctl syscall ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-6.1' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-1009-oem", ver:"6.1.0-1009.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.1.0.1009.9", rls:"UBUNTU22.04 LTS"))) {
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

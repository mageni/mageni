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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4162.2");
  script_cve_id("CVE-2018-21008", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15505", "CVE-2019-15902", "CVE-2019-15918");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-04 05:15:00 +0000 (Wed, 04 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-4162-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4162-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4162-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-4162-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4162-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. This update provides the corresponding updates for the Linux
kernel for Microsoft Azure Cloud systems for Ubuntu 14.04 ESM.

It was discovered that the RSI 91x Wi-Fi driver in the Linux kernel did not
did not handle detach operations correctly, leading to a use-after-free
vulnerability. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-21008)

Wen Huang discovered that the Marvell Wi-Fi device driver in the Linux
kernel did not properly perform bounds checking, leading to a heap
overflow. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-14814,
CVE-2019-14815, CVE-2019-14816)

Matt Delco discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform bounds checking when handling coalesced
MMIO write operations. A local attacker with write access to /dev/kvm could
use this to cause a denial of service (system crash). (CVE-2019-14821)

Hui Peng and Mathias Payer discovered that the USB audio driver for the
Linux kernel did not properly validate device meta data. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15117)

Hui Peng and Mathias Payer discovered that the USB audio driver for the
Linux kernel improperly performed recursion while handling device meta
data. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15118)

It was discovered that the Technisat DVB-S/S2 USB device driver in the
Linux kernel contained a buffer overread. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2019-15505)

Brad Spengler discovered that a Spectre mitigation was improperly
implemented in the ptrace subsystem of the Linux kernel. A local attacker
could possibly use this to expose sensitive information. (CVE-2019-15902)

It was discovered that the SMB networking file system implementation in the
Linux kernel contained a buffer overread. An attacker could use this to
expose sensitive information (kernel memory). (CVE-2019-15918)");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1061-azure", ver:"4.15.0-1061.66~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1061.47", rls:"UBUNTU14.04 LTS"))) {
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

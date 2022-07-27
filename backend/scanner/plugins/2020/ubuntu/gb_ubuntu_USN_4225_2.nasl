# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.844298");
  script_version("2020-01-23T07:59:05+0000");
  script_cve_id("CVE-2019-14895", "CVE-2019-14901", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-16231", "CVE-2019-18660", "CVE-2019-19045", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19055", "CVE-2019-19072", "CVE-2019-19524", "CVE-2019-19529", "CVE-2019-19534", "CVE-2019-18813");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 07:59:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-19 04:00:59 +0000 (Sun, 19 Jan 2020)");
  script_name("Ubuntu Update for linux-hwe USN-4225-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005277.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe'
  package(s) announced via the USN-4225-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4225-1 fixed vulnerabilities in the Linux kernel for Ubuntu 19.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 19.10 for Ubuntu 18.04 LTS.

It was discovered that a heap-based buffer overflow existed in the Marvell
WiFi-Ex Driver for the Linux kernel. A physically proximate attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-14895, CVE-2019-14901)

It was discovered that a heap-based buffer overflow existed in the Marvell
Libertas WLAN Driver for the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-14896, CVE-2019-14897)

It was discovered that the Fujitsu ES network device driver for the Linux
kernel did not properly check for errors in some situations, leading to a
NULL pointer dereference. A local attacker could use this to cause a denial
of service. (CVE-2019-16231)

Anthony Steinhauser discovered that the Linux kernel did not properly
perform Spectre_RSB mitigations to all processors for PowerPC architecture
systems in some situations. A local attacker could use this to expose
sensitive information. (CVE-2019-18660)

It was discovered that the Mellanox Technologies Innova driver in the Linux
kernel did not properly deallocate memory in certain failure conditions. A
local attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19045)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did
not properly deallocate memory in certain situations. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19051)

It was discovered that Geschwister Schneider USB CAN interface driver in
the Linux kernel did not properly deallocate memory in certain failure
conditions. A physically proximate attacker could use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-19052)

It was discovered that the netlink-based 802.11 configuration interface in
the Linux kernel did not deallocate memory in certain error conditions. A
local attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19055)

It was discovered that the event tracing subsystem of the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19072)

It was discovered that the driver for memoryless force-feedback input
devices in the Linux ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-hwe' package(s) on Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-26-generic", ver:"5.3.0-26.28~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-26-generic-lpae", ver:"5.3.0-26.28~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-26-lowlatency", ver:"5.3.0-26.28~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.3.0.26.95", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.3.0.26.95", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.3.0.26.95", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.3.0.26.95", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.3.0.26.95", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
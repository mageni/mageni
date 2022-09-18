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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2020.4286.2");
  script_cve_id("CVE-2019-14615", "CVE-2019-15217", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-17351", "CVE-2019-19051", "CVE-2019-19056", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4286-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4286-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4286-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial' package(s) announced via the USN-4286-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4286-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 ESM.

It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors. A
local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that a race condition existed in the Softmac USB Prism54
device driver in the Linux kernel. A physically proximate attacker could
use this to cause a denial of service (system crash). (CVE-2019-15220)

Julien Grall discovered that the Xen balloon memory driver in the Linux
kernel did not properly restrict the amount of memory set aside for page
mappings in some situations. An attacker could use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-17351)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did
not properly deallocate memory in certain situations. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19051)

It was discovered that the Marvell Wi-Fi device driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to possibly cause a denial of service (kernel
memory exhaustion). (CVE-2019-19056)

It was discovered that the Brocade BFA Fibre Channel device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19066)

It was discovered that the Realtek RTL8xxx USB Wi-Fi device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19068)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer dereference. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19965)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
implementation in the Linux kernel did not properly deallocate memory in
certain error conditions. An attacker could possibly use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-20096)

Mitchell Frank discovered that the Wi-Fi implementation in the Linux kernel
when used as an access point would send IAPP location updates for stations
before client authentication had completed. A physically proximate attacker
could use this to cause a denial of service. (CVE-2019-5108)

It was discovered that ZR364XX Camera USB device driver for the Linux
kernel did not properly initialize memory. A physically proximate attacker
could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1062-aws", ver:"4.4.0-1062.66", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-generic-lpae", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-generic", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-lowlatency", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-powerpc-e500mc", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-powerpc-smp", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-powerpc64-emb", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-174-powerpc64-smp", ver:"4.4.0-174.204~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1062.63", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.174.153", rls:"UBUNTU14.04 LTS"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.845322");
  script_version("2022-04-14T11:53:12+0000");
  script_cve_id("CVE-2022-1055", "CVE-2022-0492", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-4135", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45480", "CVE-2022-0435", "CVE-2022-27666");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:53:12 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-14 01:00:30 +0000 (Thu, 14 Apr 2022)");
  script_name("Ubuntu: Security Advisory for linux-bluefield (USN-5377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5377-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-April/006503.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield'
  package(s) announced via the USN-5377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the network traffic control implementation in the
Linux kernel contained a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-1055)

Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the
Linux kernel did not properly restrict access to the cgroups v1
release_agent feature. A local attacker could use this to gain
administrative privileges. (CVE-2022-0492)

Jürgen Groß discovered that the Xen subsystem within the Linux kernel did
not adequately limit the number of events driver domains (unprivileged PV
backends) could send to other guest VMs. An attacker in a driver domain
could use this to cause a denial of service in other guest VMs.
(CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

Jürgen Groß discovered that the Xen network backend driver in the Linux
kernel did not adequately limit the amount of queued packets when a guest
did not process them. An attacker in a guest VM can use this to cause a
denial of service (excessive kernel memory consumption) in the network
backend domain. (CVE-2021-28714, CVE-2021-28715)

It was discovered that the simulated networking device driver for the Linux
kernel did not properly initialize memory in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-4135)

Brendan Dolan-Gavitt discovered that the Marvell WiFi-Ex USB device driver
in the Linux kernel did not properly handle some error conditions. A
physically proximate attacker could use this to cause a denial of service
(system crash). (CVE-2021-43976)

It was discovered that the ARM Trusted Execution Environment (TEE)
subsystem in the Linux kernel contained a race condition leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service or possibly execute arbitrary code. (CVE-2021-44733)

It was discovered that the Phone Network protocol (PhoNet) implementation
in the Linux kernel did not properly perform reference counting in some
error conditions. A local attacker could possibly use this to cause a
denial of service (memory exhaustion). (CVE-2021-45095)

Wenqing Liu discovered that the f2fs file system in the Linux kernel did
not properly validate the last xattr entry in an inode. An attacker could
use this to construct a malicious f2fs image that, when mounted and
operated on, could cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-45469)

It was discovered that the Reliable Datagram Sockets (RDS) protocol
impl ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-bluefield' package(s) on Ubuntu 20.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1032-bluefield", ver:"5.4.0-1032.35", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1032.33", rls:"UBUNTU20.04 LTS"))) {
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
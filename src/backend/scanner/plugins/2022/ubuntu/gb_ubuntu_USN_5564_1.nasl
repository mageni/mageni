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
  script_oid("1.3.6.1.4.1.25623.1.0.845475");
  script_version("2022-08-17T08:41:06+0000");
  script_cve_id("CVE-2022-2588", "CVE-2022-2586", "CVE-2022-2585", "CVE-2022-0500", "CVE-2022-1652", "CVE-2022-1679", "CVE-2022-1734", "CVE-2022-1789", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-28893", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-33981", "CVE-2022-34918");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-17 08:41:06 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:40:00 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-08-11 01:00:51 +0000 (Thu, 11 Aug 2022)");
  script_name("Ubuntu: Security Advisory for linux-intel-iotg (USN-5564-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5564-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-August/006725.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg'
  package(s) announced via the USN-5564-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhenpeng Lin discovered that the network packet scheduler implementation in
the Linux kernel did not properly remove all references to a route filter
before freeing it in some situations. A local attacker could use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-2588)

It was discovered that the netfilter subsystem of the Linux kernel did not
prevent one nft object from referencing an nft set in another nft table,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-2586)

It was discovered that the implementation of POSIX timers in the Linux
kernel did not properly clean up timers in some situations. A local
attacker could use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2022-2585)

It was discovered that the eBPF implementation in the Linux kernel did not
properly prevent writes to kernel objects in BPF_BTF_LOAD commands. A
privileged local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-0500)

Minh Yuan discovered that the floppy disk driver in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2022-1652)

It was discovered that the Atheros ath9k wireless device driver in the
Linux kernel did not properly handle some error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-1679)

It was discovered that the Marvell NFC device driver implementation in the
Linux kernel did not properly perform memory cleanup operations in some
situations, leading to a use-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2022-1734)

Yongkang Jia discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle guest TLB mapping invalidation requests in
some situations. An attacker in a guest VM could use this to cause a denial
of service (system crash) in the host OS. (CVE-2022-1789)

Duoming Zhou discovered a race condition in the NFC subsystem in the Linux
kernel, leading to a use-after-free vulnerability. A privileged local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-1974)

Duoming Zhou discov ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-intel-iotg' package(s) on Ubuntu 22.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1013-intel-iotg", ver:"5.15.0-1013.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1013.13", rls:"UBUNTU22.04 LTS"))) {
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
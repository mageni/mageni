# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817723");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2021-28688", "CVE-2021-28951", "CVE-2021-28952", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29264", "CVE-2021-29266", "CVE-2021-29646", "CVE-2021-29647", "CVE-2021-29649", "CVE-2021-29650", "CVE-2021-29657", "CVE-2021-31916", "CVE-2021-3483");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-12 03:00:32 +0000 (Wed, 12 May 2021)");
  script_name("Ubuntu: Security Advisory for linux-oem-5.10 (USN-4948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-4948-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/006016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.10'
  package(s) announced via the USN-4948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryota Shiga discovered that the eBPF implementation in the Linux kernel did
not properly verify that a BPF program only reserved as much memory for a
ring buffer as was allocated. A local attacker could use this to cause a
denial of service (system crash) or execute arbitrary code. (CVE-2021-3489)

Manfred Paul discovered that the eBPF implementation in the Linux kernel
did not properly track bounds on bitwise operations. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2021-3490)

Billy Jheng Bing-Jhong discovered that the io_uring implementation of the
Linux kernel did not properly enforce the MAX_RW_COUNT limit in some
situations. A local attacker could use this to cause a denial of service
(system crash) or execute arbitrary code. (CVE-2021-3491)

Kiyin () discovered that the NFC LLCP protocol implementation in the
Linux kernel contained a reference counting error. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25670)

Kiyin () discovered that the NFC LLCP protocol implementation in the
Linux kernel did not properly deallocate memory in certain error
situations. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

It was discovered that the Xen paravirtualization backend in the Linux
kernel did not properly deallocate memory in some situations. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2021-28688)

It was discovered that the io_uring subsystem in the Linux kernel contained
a race condition leading to a deadlock condition. A local attacker could
use this to cause a denial of service. (CVE-2021-28951)

John Stultz discovered that the audio driver for Qualcomm SDM845 systems in
the Linux kernel did not properly validate port ID numbers. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-28952)

Zygo Blaxell discovered that the btrfs file system implementation in the
Linux kernel contained a race condition during certain cloning operations.
A local attacker could possibly use this to cause a denial of service
(system crash). (CVE-2021-28964)

Vince Weaver discovered that the perf subsystem in the Linux kernel did
not properly handle certain PEBS records properly for some Intel Haswell
processors. A local attacker could use this cause a denial of service
(system crash). (CVE-2021-28971)

It was discovered that the RPA PCI Hotplug driver implementation in the
Linux kernel did not properly handle dev ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-oem-5.10' package(s) on Ubuntu 20.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-1026-oem", ver:"5.10.0-1026.27", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.10.0.1026.27", rls:"UBUNTU20.04 LTS"))) {
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

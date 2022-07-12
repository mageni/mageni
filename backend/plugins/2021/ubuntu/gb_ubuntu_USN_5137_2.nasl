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
  script_oid("1.3.6.1.4.1.25623.1.0.845127");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2019-19449", "CVE-2020-36385", "CVE-2021-3428", "CVE-2021-34556", "CVE-2021-35477", "CVE-2021-3739", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-3759");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-12 02:00:32 +0000 (Fri, 12 Nov 2021)");
  script_name("Ubuntu: Security Advisory for linux-bluefield (USN-5137-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5137-2");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-November/006274.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield'
  package(s) announced via the USN-5137-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the f2fs file system in the Linux kernel did not
properly validate metadata in some situations. An attacker could use this
to construct a malicious f2fs image that, when mounted and operated on,
could cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-19449)

It was discovered that the Infiniband RDMA userspace connection manager
implementation in the Linux kernel contained a race condition leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possible execute arbitrary code.
(CVE-2020-36385)

Wolfgang Frisch discovered that the ext4 file system implementation in the
Linux kernel contained an integer overflow when handling metadata inode
extents. An attacker could use this to construct a malicious ext4 file
system image that, when mounted, could cause a denial of service (system
crash). (CVE-2021-3428)

Benedict Schlueter discovered that the BPF subsystem in the Linux kernel
did not properly protect against Speculative Store Bypass (SSB) side-
channel attacks in some situations. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-34556)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly protect against Speculative Store Bypass (SSB) side-channel
attacks in some situations. A local attacker could possibly use this to
expose sensitive information. (CVE-2021-35477)

It was discovered that the btrfs file system in the Linux kernel did not
properly handle removing a non-existent device id. An attacker with
CAP_SYS_ADMIN could use this to cause a denial of service. (CVE-2021-3739)

It was discovered that the Qualcomm IPC Router protocol implementation in
the Linux kernel did not properly validate metadata in some situations. A
local attacker could use this to cause a denial of service (system crash)
or expose sensitive information. (CVE-2021-3743)

It was discovered that the virtual terminal (vt) device implementation in
the Linux kernel contained a race condition in its ioctl handling that led
to an out-of-bounds read vulnerability. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-3753)

It was discovered that the Linux kernel did not properly account for the
memory usage of certain IPC objects. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2021-3759)");

  script_tag(name:"affected", value:"'linux-bluefield' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1055-gke", ver:"5.4.0-1055.58~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1057-oracle", ver:"5.4.0-1057.61~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.4", ver:"5.4.0.1055.58~18.04.20", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.4.0.1057.61~18.04.37", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1021-bluefield", ver:"5.4.0-1021.24", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1057-oracle", ver:"5.4.0-1057.61", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1021.22", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-20.04", ver:"5.4.0.1057.57", rls:"UBUNTU20.04 LTS"))) {
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
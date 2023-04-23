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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6013.1");
  script_cve_id("CVE-2020-36516", "CVE-2021-26401", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-3428", "CVE-2021-3659", "CVE-2021-3669", "CVE-2021-3732", "CVE-2021-3772", "CVE-2021-4149", "CVE-2021-4203", "CVE-2021-45868", "CVE-2022-0487", "CVE-2022-0494", "CVE-2022-0617", "CVE-2022-1016", "CVE-2022-1195", "CVE-2022-1205", "CVE-2022-1462", "CVE-2022-1516", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-20132", "CVE-2022-20572", "CVE-2022-2318", "CVE-2022-2380", "CVE-2022-2503", "CVE-2022-2663", "CVE-2022-2991", "CVE-2022-3061", "CVE-2022-3111", "CVE-2022-3303", "CVE-2022-3628", "CVE-2022-36280", "CVE-2022-3646", "CVE-2022-36879", "CVE-2022-3903", "CVE-2022-39188", "CVE-2022-41218", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-0394", "CVE-2023-1074", "CVE-2023-1095", "CVE-2023-1118", "CVE-2023-23455", "CVE-2023-26545", "CVE-2023-26607");
  script_tag(name:"creation_date", value:"2023-04-13 04:09:11 +0000 (Thu, 13 Apr 2023)");
  script_version("2023-04-19T10:08:55+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 04:59:00 +0000 (Fri, 10 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6013-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6013-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-6013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xuewei Feng, Chuanpu Fu, Qi Li, Kun Sun, and Ke Xu discovered that the TCP
implementation in the Linux kernel did not properly handle IPID assignment.
A remote attacker could use this to cause a denial of service (connection
termination) or inject forged data. (CVE-2020-36516)

Ke Sun, Alyssa Milburn, Henrique Kawakami, Emma Benoit, Igor Chervatyuk,
Lisa Aichele, and Thais Moreira Hamasaki discovered that the Spectre
Variant 2 mitigations for AMD processors on Linux were insufficient in some
situations. A local attacker could possibly use this to expose sensitive
information. (CVE-2021-26401)

Jurgen Gross discovered that the Xen subsystem within the Linux kernel did
not adequately limit the number of events driver domains (unprivileged PV
backends) could send to other guest VMs. An attacker in a driver domain
could use this to cause a denial of service in other guest VMs.
(CVE-2021-28712, CVE-2021-28713)

Wolfgang Frisch discovered that the ext4 file system implementation in the
Linux kernel contained an integer overflow when handling metadata inode
extents. An attacker could use this to construct a malicious ext4 file
system image that, when mounted, could cause a denial of service (system
crash). (CVE-2021-3428)

It was discovered that the IEEE 802.15.4 wireless network subsystem in the
Linux kernel did not properly handle certain error conditions, leading to a
null pointer dereference vulnerability. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2021-3659)

It was discovered that the System V IPC implementation in the Linux kernel
did not properly handle large shared memory counts. A local attacker could
use this to cause a denial of service (memory exhaustion). (CVE-2021-3669)

Alois Wohlschlager discovered that the overlay file system in the Linux
kernel did not restrict private clones in some situations. An attacker
could use this to expose sensitive information. (CVE-2021-3732)

It was discovered that the SCTP protocol implementation in the Linux kernel
did not properly verify VTAGs in some situations. A remote attacker could
possibly use this to cause a denial of service (connection disassociation).
(CVE-2021-3772)

It was discovered that the btrfs file system implementation in the Linux
kernel did not properly handle locking in certain error conditions. A local
attacker could use this to cause a denial of service (kernel deadlock).
(CVE-2021-4149)

Jann Horn discovered that the socket subsystem in the Linux kernel
contained a race condition when handling listen() and connect() operations,
leading to a read-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2021-4203)

It was discovered that the file system quotas implementation in the Linux
kernel did not properly validate the quota block number. An attacker could
use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1117-aws", ver:"4.4.0-1117.123", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1117.114", rls:"UBUNTU14.04 LTS"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3620.2");
  script_cve_id("CVE-2017-11089", "CVE-2017-12762", "CVE-2017-17448", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17807", "CVE-2017-5715", "CVE-2018-1000026", "CVE-2018-5332");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-06 01:29:00 +0000 (Fri, 06 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3620-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3620-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3620-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3620-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3620-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 ESM.

Jann Horn discovered that microprocessors utilizing speculative execution
and branch prediction may allow unauthorized memory reads via sidechannel
attacks. This flaw is known as Spectre. A local attacker could use this to
expose sensitive information, including kernel memory. (CVE-2017-5715)

It was discovered that the netlink 802.11 configuration interface in the
Linux kernel did not properly validate some attributes passed from
userspace. A local attacker with the CAP_NET_ADMIN privilege could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-11089)

It was discovered that a buffer overflow existed in the ioctl handling code
in the ISDN subsystem of the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-12762)

It was discovered that the netfilter component of the Linux did not
properly restrict access to the connection tracking helpers list. A local
attacker could use this to bypass intended access restrictions.
(CVE-2017-17448)

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
contained an out-of-bounds read when handling memory-mapped I/O. A local
attacker could use this to expose sensitive information. (CVE-2017-17741)

It was discovered that the Salsa20 encryption algorithm implementations in
the Linux kernel did not properly handle zero-length inputs. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-17805)

It was discovered that the keyring implementation in the Linux kernel did
not properly check permissions when a key request was performed on a
task's default keyring. A local attacker could use this to add keys to
unauthorized keyrings. (CVE-2017-17807)

It was discovered that the Broadcom NetXtremeII ethernet driver in the
Linux kernel did not properly validate Generic Segment Offload (GSO) packet
sizes. An attacker could use this to cause a denial of service (interface
unavailability). (CVE-2018-1000026)

It was discovered that the Reliable Datagram Socket (RDS) implementation in
the Linux kernel contained an out-of-bounds write during RDMA page
allocation. An attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-5332)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-144-generic-lpae", ver:"3.13.0-144.193~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-144-generic", ver:"3.13.0-144.193~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.144.135", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.144.135", rls:"UBUNTU12.04 LTS"))) {
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

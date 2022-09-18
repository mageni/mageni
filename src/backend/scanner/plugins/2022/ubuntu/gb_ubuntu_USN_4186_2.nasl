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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4186.2");
  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135", "CVE-2019-15098", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17666");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-24 19:15:00 +0000 (Thu, 24 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4186-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4186-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4186-2");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/TAA_MCEPSC_i915");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial' package(s) announced via the USN-4186-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4186-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 ESM.

Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo,
Kaveh Razavi, Herbert Bos, Cristiano Giuffrida, Giorgi Maisuradze, Moritz
Lipp, Michael Schwarz, Daniel Gruss, and Jo Van Bulck discovered that Intel
processors using Transactional Synchronization Extensions (TSX) could
expose memory contents previously stored in microarchitectural buffers to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11135)

It was discovered that the Intel i915 graphics chipsets allowed userspace
to modify page table entries via writes to MMIO from the Blitter Command
Streamer and expose kernel memory information. A local attacker could use
this to expose sensitive information or possibly elevate privileges.
(CVE-2019-0155)

Deepak Gupta discovered that on certain Intel processors, the Linux kernel
did not properly perform invalidation on page table updates by virtual
guest operating systems. A local attacker in a guest VM could use this to
cause a denial of service (host system crash). (CVE-2018-12207)

It was discovered that the Intel i915 graphics chipsets could cause a
system hang when userspace performed a read from GT memory mapped input
output (MMIO) when the product is in certain low power states. A local
attacker could use this to cause a denial of service. (CVE-2019-0154)

Hui Peng discovered that the Atheros AR6004 USB Wi-Fi device driver for the
Linux kernel did not properly validate endpoint descriptors returned by the
device. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15098)

Ori Nimron discovered that the AX25 network protocol implementation in the
Linux kernel did not properly perform permissions checks. A local attacker
could use this to create a raw socket. (CVE-2019-17052)

Ori Nimron discovered that the IEEE 802.15.4 Low-Rate Wireless network
protocol implementation in the Linux kernel did not properly perform
permissions checks. A local attacker could use this to create a raw socket.
(CVE-2019-17053)

Ori Nimron discovered that the Appletalk network protocol implementation in
the Linux kernel did not properly perform permissions checks. A local
attacker could use this to create a raw socket. (CVE-2019-17054)

Ori Nimron discovered that the modular ISDN network protocol implementation
in the Linux kernel did not properly perform permissions checks. A local
attacker could use this to create a raw socket. (CVE-2019-17055)

Ori Nimron discovered that the Near field Communication (NFC) network
protocol implementation in the Linux kernel did not properly perform
permissions checks. A local attacker could use ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1058-aws", ver:"4.4.0-1058.62", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-generic-lpae", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-generic", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-lowlatency", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-powerpc-e500mc", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-powerpc-smp", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-powerpc64-emb", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-168-powerpc64-smp", ver:"4.4.0-168.197~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1058.59", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.168.147", rls:"UBUNTU14.04 LTS"))) {
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

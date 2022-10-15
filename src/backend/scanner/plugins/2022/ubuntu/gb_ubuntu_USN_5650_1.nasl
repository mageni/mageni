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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5650.1");
  script_cve_id("CVE-2021-33655", "CVE-2021-33656", "CVE-2021-4037", "CVE-2022-0850", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1729", "CVE-2022-20368", "CVE-2022-2639", "CVE-2022-2964", "CVE-2022-2978", "CVE-2022-3028", "CVE-2022-3202", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-10-03 04:28:47 +0000 (Mon, 03 Oct 2022)");
  script_version("2022-10-03T10:13:16+0000");
  script_tag(name:"last_modification", value:"2022-10-03 10:13:16 +0000 (Mon, 03 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-30 19:19:00 +0000 (Tue, 30 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5650-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5650-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5650-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-5650-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the framebuffer driver on the Linux kernel did not
verify size limits when changing font or screen size, leading to an out-of-
bounds write. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-33655)

It was discovered that the virtual terminal driver in the Linux kernel did
not properly handle VGA console font changes, leading to an out-of-bounds
write. A local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2021-33656)

Christian Brauner discovered that the XFS file system implementation in the
Linux kernel did not properly handle setgid file creation. A local attacker
could use this to gain elevated privileges. (CVE-2021-4037)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly initialize memory in some situations. A privileged
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2022-0850)

Duoming Zhou discovered that the AX.25 amateur radio protocol
implementation in the Linux kernel did not handle detach events properly in
some situations. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-1199)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel during device detach operations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1204)

Norbert Slusarek discovered that a race condition existed in the perf
subsystem in the Linux kernel, resulting in a use-after-free vulnerability.
A privileged local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-1729)

It was discovered that the Packet network protocol implementation in the
Linux kernel contained an out-of-bounds access. A remote attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-20368)

It was discovered that the Open vSwitch implementation in the Linux kernel
contained an out of bounds write vulnerability in certain situations. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-2639)

Jann Horn discovered that the ASIX AX88179/178A USB Ethernet driver in the
Linux kernel contained multiple out-of-bounds vulnerabilities. A local
attacker with physical access could plug in a specially crafted USB device
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-2964)

Hao Sun and Jiacheng Xu discovered that the NILFS file system
implementation in the Linux kernel contained a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1113-aws", ver:"4.4.0-1113.119", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-234-generic", ver:"4.4.0-234.268~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-234-lowlatency", ver:"4.4.0-234.268~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1113.110", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.234.203", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.234.203", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.234.203", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1114-kvm", ver:"4.4.0-1114.124", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1151-aws", ver:"4.4.0-1151.166", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-234-generic", ver:"4.4.0-234.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-234-lowlatency", ver:"4.4.0-234.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1151.155", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.234.240", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1114.111", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.234.240", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.234.240", rls:"UBUNTU16.04 LTS"))) {
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

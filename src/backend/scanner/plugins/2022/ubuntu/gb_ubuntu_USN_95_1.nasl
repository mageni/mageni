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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.95.1");
  script_cve_id("CVE-2005-0209", "CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0529", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0532", "CVE-2005-0736");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-95-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-95-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-95-1");
  script_xref(name:"URL", value:"https://bugzilla.ubuntulinux.org/show_bug.cgi?id=6749");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.8.1' package(s) announced via the USN-95-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A remote Denial of Service vulnerability was discovered in the
Netfilter IP packet handler. This allowed a remote attacker to crash
the machine by sending specially crafted IP packet fragments.
(CAN-2005-0209)

The Netfilter code also contained a memory leak. Certain locally
generated packet fragments are reassembled twice, which caused a
double allocation of a data structure. This could be locally exploited
to crash the machine due to kernel memory exhaustion. (CAN-2005-0210)

Ben Martel and Stephen Blackheath found a remote Denial of Service
vulnerability in the PPP driver. This allowed a malicious pppd client
to crash the server machine. (CAN-2005-0384)

Georgi Guninski discovered a buffer overflow in the ATM driver. The
atm_get_addr() function does not validate its arguments sufficiently,
which could allow a local attacker to overwrite large portions of
kernel memory by supplying a negative length argument. This could
eventually lead to arbitrary code execution. (CAN-2005-0531)

Georgi Guninski also discovered three other integer comparison
problems in the TTY layer, in the /proc interface and the ReiserFS
driver. However, the previous Ubuntu security update (kernel version
2.6.8.1-16.11) already contained a patch which checks the arguments to
these functions at a higher level and thus prevents these flaws from
being exploited. (CAN-2005-0529, CAN-2005-0530, CAN-2005-0532)

Georgi Guninski discovered an integer overflow in the sys_epoll_wait()
function which allowed local users to overwrite the first few kB of
physical memory. However, very few applications actually use this
space (dosemu is a notable exception), but potentially this could lead
to privilege escalation. (CAN-2005-0736)

Eric Anholt discovered a race condition in the Radeon DRI driver. In
some cases this allowed a local user with DRI privileges on a Radeon
card to execute arbitrary code with root privileges.

Finally this update fixes a regression in the NFS server driver
which was introduced in the previous security update (kernel version
2.6.8.1-16.11). We apologize for the inconvenience.
([link moved to references])");

  script_tag(name:"affected", value:"'linux-source-2.6.8.1' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.8.1", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-386", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-686-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-686", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-generic", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-k8-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-k8", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-xeon", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-k7-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-k7", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power3-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power3", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power4-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power4", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-powerpc-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-powerpc", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-386", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-686-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-686", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-generic", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-k8-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-k8", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-xeon", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-k7-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-k7", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power3-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power3", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power4-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power4", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-powerpc-smp", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-powerpc", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.8.1", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.8.1", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.8.1", ver:"2.6.8.1-16.12", rls:"UBUNTU4.10"))) {
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

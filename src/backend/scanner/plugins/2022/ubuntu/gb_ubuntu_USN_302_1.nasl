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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.302.1");
  script_cve_id("CVE-2006-0038", "CVE-2006-0744", "CVE-2006-1055", "CVE-2006-1056", "CVE-2006-1522", "CVE-2006-1527", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1859", "CVE-2006-1860", "CVE-2006-1864", "CVE-2006-2071", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274", "CVE-2006-2275", "CVE-2006-2444");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_name("Ubuntu: Security Advisory (USN-302-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-302-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-302-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta, linux-restricted-modules-2.6.15, linux-source-2.6.10, linux-source-2.6.12, linux-source-2.6.15' package(s) announced via the USN-302-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow was discovered in the do_replace() function. A
local user process with the CAP_NET_ADMIN capability could exploit
this to execute arbitrary commands with full root privileges.
However, none of Ubuntu's supported packages use this capability with
any non-root user, so this only affects you if you use some third
party software like the OpenVZ virtualization system. (CVE-2006-0038)

On EMT64 CPUs, the kernel did not properly handle uncanonical return
addresses. A local user could exploit this to trigger a kernel crash.
(CVE-2006-0744)

Al Viro discovered a local Denial of Service in the sysfs write buffer
handling. By writing a block with a length exactly equal to the
processor's page size to any writable file in /sys, a local attacker
could cause a kernel crash. (CVE-2006-1055)

Jan Beulich discovered an information leak in the handling of
registers for the numeric coprocessor when running on AMD processors.
This allowed processes to see the coprocessor execution state of
other processes, which could reveal sensitive data in the case of
cryptographic computations. (CVE-2006-1056)

Marcel Holtmann discovered that the sys_add_key() did not check that
a new user key is added to a proper keyring. By attempting to add a
key to a normal user key (which is not a keyring), a local attacker
could exploit this to crash the kernel. (CVE-2006-1522)

Ingo Molnar discovered that the SCTP protocol connection tracking
module in netfilter got stuck in an infinite loop on certain empty
packet chunks. A remote attacker could exploit this to cause the
computer to hang. (CVE-2006-1527)

The SCSI I/O driver did not correctly handle the VM_IO flag for memory
mapped pages used for data transfer. A local user could exploit this
to cause a kernel crash. (CVE-2006-1528)

The choose_new_parent() contained obsolete debugging code. A local
user could exploit this to cause a kernel crash. (CVE-2006-1855)

Kostik Belousov discovered that the readv() and writev() functions did
not query LSM modules for access permission. This could be exploited
to circumvent access restrictions defined by LSM modules such as
SELinux or AppArmor. (CVE-2006-1856)

The SCTP driver did not properly verify certain parameters when
receiving a HB-ACK chunk. By sending a specially crafted packet to an
SCTP socket, a remote attacker could exploit this to trigger a buffer
overflow, which could lead to a crash or possibly even arbitrary code
execution. (CVE-2006-1857)

The sctp_walk_params() function in the SCTP driver incorrectly used
rounded values for bounds checking instead of the precise values. By
sending a specially crafted packet to an SCTP socket, a remote
attacker could exploit this to crash the kernel. (CVE-2006-1858)

Bjoern Steinbrink reported a memory leak in the __setlease() function.
A local attacker could exploit this to exhaust kernel memory and
render the computer unusable (Denial of Service). ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-meta, linux-restricted-modules-2.6.15, linux-source-2.6.10, linux-source-2.6.12, linux-source-2.6.15' package(s) on Ubuntu 5.04, Ubuntu 5.10, Ubuntu 6.06.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-386", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-686-smp", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-686", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-generic", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-k8-smp", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-k8", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-xeon", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-k7-smp", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-k7", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power3-smp", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power3", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power4-smp", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power4", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-powerpc-smp", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-powerpc", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.10", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.10", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.10", ver:"2.6.10-34.20", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-386", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686-smp", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-generic", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8-smp", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-xeon", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7-smp", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc-smp", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc64-smp", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.12", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.12", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.12", ver:"2.6.12-10.34", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"avm-fritz-firmware-2.6.15-25", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fglrx-control", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fglrx-kernel-source", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-386", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-686-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-686", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-generic", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-k8-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-k8", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-server", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-amd64-xeon", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-386", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-686", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-amd64-generic", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-amd64-k8", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-amd64-server", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-amd64-xeon", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-k7", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-powerpc-smp", ver:"6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-powerpc", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-powerpc64-smp", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-server-bigiron", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-25-server", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-386", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-generic", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-k8", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-server", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-xeon", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-k7", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power3-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power3", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power4-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-power4", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-server-bigiron", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-server", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-k7-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-k7", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power3-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power3", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power4-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-power4", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-powerpc-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-powerpc", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-powerpc64-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-386", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-686", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-amd64-generic", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-amd64-k8", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-amd64-xeon", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-k7", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-powerpc-smp", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-25-powerpc", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-386", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-686", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-generic", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-k8", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-xeon", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-k7", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-powerpc-smp", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-powerpc", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-server-bigiron", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-server", ver:"2.6.15.23", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.15", ver:"2.6.15-25.43", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-glx", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"2.6.15.11-2", rls:"UBUNTU6.06 LTS"))) {
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

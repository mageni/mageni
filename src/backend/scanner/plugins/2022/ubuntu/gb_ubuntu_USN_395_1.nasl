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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.395.1");
  script_cve_id("CVE-2006-4572", "CVE-2006-4813", "CVE-2006-4997", "CVE-2006-5158", "CVE-2006-5173", "CVE-2006-5619", "CVE-2006-5648", "CVE-2006-5649", "CVE-2006-5701", "CVE-2006-5751");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-395-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.10|6\.06\ LTS|6\.10)");

  script_xref(name:"Advisory-ID", value:"USN-395-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-395-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.12, linux-source-2.6.15, linux-source-2.6.17' package(s) announced via the USN-395-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mark Dowd discovered that the netfilter iptables module did not
correctly handle fragmented packets. By sending specially crafted
packets, a remote attacker could exploit this to bypass firewall
rules. This has only be fixed for Ubuntu 6.10, the corresponding fix
for Ubuntu 5.10 and 6.06 will follow soon. (CVE-2006-4572)

Dmitriy Monakhov discovered an information leak in the
__block_prepare_write() function. During error recovery, this function
did not properly clear memory buffers which could allow local users to
read portions of unlinked files. This only affects Ubuntu 5.10.
(CVE-2006-4813)

ADLab Venustech Info Ltd discovered that the ATM network driver
referenced an already released pointer in some circumstances. By
sending specially crafted packets to a host over ATM, a remote
attacker could exploit this to crash that host. This does not affect
Ubuntu 6.10. (CVE-2006-4997)

Matthias Andree discovered that the NFS locking management daemon
(lockd) did not correctly handle mixing of 'lock' and 'nolock' option
mounts on the same client. A remote attacker could exploit this to
crash lockd and thus rendering the NFS imports inaccessible. This only
affects Ubuntu 5.10. (CVE-2006-5158)

The task switching code did not save and restore EFLAGS of processes.
By starting a specially crafted executable, a local attacker could
exploit this to eventually crash many other running processes. This
does not affect Ubuntu 6.10. (CVE-2006-5173)

James Morris discovered that the ip6fl_get_n() function incorrectly
handled flow labels. A local attacker could exploit this to crash the
kernel. (CVE-2006-5619)

Fabio Massimo Di Nitto discovered that the sys_get_robust_list and
sys_set_robust_list system calls lacked proper lock handling on the
powerpc platform. A local attacker could exploit this to create
unkillable processes, drain all available CPU/memory, and render the
machine unrebootable. This only affects Ubuntu 6.10. (CVE-2006-5648)

Fabio Massimo Di Nitto discovered a flaw in the alignment check
exception handling on the powerpc platform. A local attacker could
exploit this to cause a kernel panic and crash the machine.
(CVE-2006-5649)

Certain corrupted squashfs file system images caused a memory
allocation to be freed twice. By mounting a specially crafted squashfs
file system, a local attacker could exploit this to crash the kernel.
This does not affect Ubuntu 5.10. (CVE-2006-5701)

An integer overflow was found in the get_fdb_entries() function of the
network bridging code. By executing a specially crafted ioctl, a local
attacker could exploit this to execute arbitrary code with root
privileges. (CVE-2006-5751)");

  script_tag(name:"affected", value:"'linux-source-2.6.12, linux-source-2.6.15, linux-source-2.6.17' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-386", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686-smp", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-generic", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8-smp", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-xeon", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7-smp", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc-smp", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc64-smp", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-sparc64-smp", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-sparc64", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.12", ver:"2.6.12-10.42", rls:"UBUNTU5.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-386", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-686", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-amd64-generic", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-amd64-k8", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-amd64-server", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-amd64-xeon", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-k7", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-powerpc-smp", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-powerpc", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-powerpc64-smp", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-server-bigiron", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-server", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-sparc64-smp", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-27-sparc64", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.15", ver:"2.6.15-27.50", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-386", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-generic", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-powerpc-smp", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-powerpc", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-powerpc64-smp", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-server-bigiron", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-server", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-sparc64-smp", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-10-sparc64", ver:"2.6.17.1-10.34", rls:"UBUNTU6.10"))) {
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

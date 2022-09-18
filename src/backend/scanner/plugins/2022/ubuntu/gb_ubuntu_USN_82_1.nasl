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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.82.1");
  script_cve_id("CVE-2004-0176", "CVE-2005-0176", "CVE-2005-0177", "CVE-2005-0178");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-82-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-82-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-82-1");
  script_xref(name:"URL", value:"http://oss.sgi.com/archives/netdev/2005-01/msg01036.html:");
  script_xref(name:"URL", value:"http://oss.sgi.com/archives/netdev/2005-01/msg01036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.8.1' package(s) announced via the USN-82-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CAN-2004-0176:

 Michael Kerrisk noticed an insufficient permission checking in the
 shmctl() function. Any process was permitted to lock/unlock any
 System V shared memory segment that fell within the
 RLIMIT_MEMLOCK limit (that is the maximum size of shared memory that
 unprivileged users can acquire). This allowed am unprivileged user
 process to unlock locked memory of other processes, thereby allowing
 them to be swapped out. Usually locked shared memory is used to
 store passphrases and other sensitive content which must not be
 written to the swap space (where it could be read out even after a
 reboot).

CAN-2005-0177:

 OGAWA Hirofumi noticed that the table sizes in nls_ascii.c were
 incorrectly set to 128 instead of 256. This caused a buffer overflow
 in some cases which could be exploited to crash the kernel.

CAN-2005-0178:

 A race condition was found in the terminal handling of the
 'setsid()' function, which is used to start new process sessions.

[link moved to references]

 David Coulson noticed a design flaw in the netfilter/iptables module.
 By sending specially crafted packets, a remote attacker could exploit
 this to crash the kernel or to bypass firewall rules.

 Fixing this vulnerability required a change in the Application
 Binary Interface (ABI) of the kernel. This means that third party
 user installed modules might not work any more with the new kernel,
 so this fixed kernel has a new ABI version number. You have to
 recompile and reinstall all third party modules.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.8.1", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-386", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-686-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-686", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-generic", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-k8-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-k8", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-amd64-xeon", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-k7-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-k7", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power3-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power3", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power4-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-power4", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-powerpc-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5-powerpc", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-5", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-386", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-686-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-686", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-generic", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-k8-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-k8", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-amd64-xeon", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-k7-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-k7", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power3-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power3", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power4-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-power4", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-powerpc-smp", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-5-powerpc", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.8.1", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.8.1", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.8.1", ver:"2.6.8.1-16.11", rls:"UBUNTU4.10"))) {
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

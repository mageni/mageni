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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2004.30.1");
  script_cve_id("CVE-2004-0882", "CVE-2004-0883", "CVE-2004-0949");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-30-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-30-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-30-1");
  script_xref(name:"URL", value:"http://isec.pl/vulnerabilities/isec-0017-binfmt_elf.txt:");
  script_xref(name:"URL", value:"http://marc.theaimsgroup.com/?l=linux-kernel&m=109776571411003&w=2:");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.8.1' package(s) announced via the USN-30-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CAN-2004-0883, CAN-2004-0949:

 During an audit of the smb file system implementation within Linux,
 several vulnerabilities were discovered ranging from out of bounds
 read accesses to kernel level buffer overflows.

 To exploit any of these vulnerabilities, an attacker needs control
 over the answers of the connected Samba server. This could be
 achieved by machine-in-the-middle attacks or by taking over the Samba
 server with e. g. the recently disclosed vulnerability in Samba 3.x
 (see CAN-2004-0882).

 While any of these vulnerabilities can be easily used as remote denial
 of service exploits against Linux systems, it is unclear if it is
 possible for a skilled local or remote attacker to use any of the
 possible buffer overflows for arbitrary code execution in kernel
 space. So these bugs may theoretically lead to privilege escalation
 and total compromise of the whole system.

[link moved to references]

 Several flaws have been found in the Linux ELF binary loader's
 handling of setuid binaries. Nowadays ELF is the standard format for
 Linux executables and libraries. setuid binaries are programs that
 have the 'setuid' file permission bit set, they allow to execute a
 program under a user id different from the calling user and are
 mostly used to allow executing a program with root privileges to
 normal users.

 The vulnerabilities that were fixed in these updated kernel packages
 could lead Denial of Service attacks. They also might lead to
 execution of arbitrary code and privilege escalation on some
 platforms if an attacker is able to run setuid programs under some
 special system conditions (like very little remaining memory).

 Another flaw could allow an attacker to read supposedly unreadable,
 but executable suid binaries. The attacker can then use this to seek
 faults within the executable.

[link moved to references]

 Bernard Gagnon discovered a memory leak in the mmap raw packet
 socket implementation. When a client application (in ELF format)
 core dumps, a region of memory stays allocated as a ring buffer.
 This could be exploited by a malicious user who repeatedly crashes
 certain types of applications until the memory is exhausted, thus
 causing a Denial of Service.

Reverted 486 emulation patch:

 Ubuntu kernels for the i386 platforms are compiled using the i486
 instruction set for performance reasons. Former Ubuntu kernels
 contained code which emulated the missing instructions on real 386
 processors. However, several actual and potential security flaws
 have been discovered in the code, and it was found to be
 unsupportable. It might be possible to exploit these vulnerabilities
 also on i486 and higher processors.

 Therefore support for real i386 processors has ceased. This updated
 kernel will only run on i486 and newer processors.

 Other architectures supported by Ubuntu (amd64, powerpc) are not
 affected.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.8.1", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-386", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-686-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-686", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-amd64-generic", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-amd64-k8-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-amd64-k8", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-amd64-xeon", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-k7-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-k7", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-power3-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-power3", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-power4-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-power4", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-powerpc-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3-powerpc", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-3", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-386", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-686-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-686", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-amd64-generic", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-amd64-k8-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-amd64-k8", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-amd64-xeon", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-k7-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-k7", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-power3-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-power3", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-power4-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-power4", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-powerpc-smp", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-3-powerpc", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.8.1", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.8.1", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.8.1", ver:"2.6.8.1-16.1", rls:"UBUNTU4.10"))) {
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

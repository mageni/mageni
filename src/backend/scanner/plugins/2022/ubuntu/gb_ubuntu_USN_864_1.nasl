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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.864.1");
  script_cve_id("CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3228", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3623", "CVE-2009-3624", "CVE-2009-3638", "CVE-2009-3722", "CVE-2009-3725", "CVE-2009-3726", "CVE-2009-3888", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4005", "CVE-2009-4026", "CVE-2009-4027");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-864-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-864-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-864-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15' package(s) announced via the USN-864-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the AX.25 network subsystem did not correctly
check integer signedness in certain setsockopt calls. A local attacker
could exploit this to crash the system, leading to a denial of service.
Ubuntu 9.10 was not affected. (CVE-2009-2909)

Jan Beulich discovered that the kernel could leak register contents to
32-bit processes that were switched to 64-bit mode. A local attacker
could run a specially crafted binary to read register values from an
earlier process, leading to a loss of privacy. (CVE-2009-2910)

Dave Jones discovered that the gdth SCSI driver did not correctly validate
array indexes in certain ioctl calls. A local attacker could exploit
this to crash the system or gain elevated privileges. (CVE-2009-3080)

Eric Dumazet and Jiri Pirko discovered that the TC and CLS subsystems
would leak kernel memory via uninitialized structure members. A local
attacker could exploit this to read several bytes of kernel memory,
leading to a loss of privacy. (CVE-2009-3228, CVE-2009-3612)

Earl Chew discovered race conditions in pipe handling. A local attacker
could exploit anonymous pipes via /proc/*/fd/ and crash the system or
gain root privileges. (CVE-2009-3547)

Dave Jones and Francois Romieu discovered that the r8169 network driver
could be made to leak kernel memory. A remote attacker could send a large
number of jumbo frames until the system memory was exhausted, leading
to a denial of service. Ubuntu 9.10 was not affected. (CVE-2009-3613).

Ben Hutchings discovered that the ATI Rage 128 video driver did not
correctly validate initialization states. A local attacker could
make specially crafted ioctl calls to crash the system or gain root
privileges. (CVE-2009-3620)

Tomoki Sekiyama discovered that Unix sockets did not correctly verify
namespaces. A local attacker could exploit this to cause a system hang,
leading to a denial of service. (CVE-2009-3621)

J. Bruce Fields discovered that NFSv4 did not correctly use the credential
cache. A local attacker using a mount with AUTH_NULL authentication
could exploit this to crash the system or gain root privileges. Only
Ubuntu 9.10 was affected. (CVE-2009-3623)

Alexander Zangerl discovered that the kernel keyring did not correctly
reference count. A local attacker could issue a series of specially
crafted keyring calls to crash the system or gain root privileges.
Only Ubuntu 9.10 was affected. (CVE-2009-3624)

David Wagner discovered that KVM did not correctly bounds-check CPUID
entries. A local attacker could exploit this to crash the system
or possibly gain elevated privileges. Ubuntu 6.06 and 9.10 were not
affected. (CVE-2009-3638)

Avi Kivity discovered that KVM did not correctly check privileges when
accessing debug registers. A local attacker could exploit this to
crash a host system from within a guest system, leading to a denial of
service. Ubuntu 6.06 and 9.10 were not affected. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-386", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-686", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-generic", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-k8", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-server", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-xeon", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa32-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa32", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa64-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa64", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-itanium-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-itanium", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-k7", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-mckinley-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-mckinley", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-powerpc-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-powerpc", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-powerpc64-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-server-bigiron", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-server", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-sparc64-smp", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-sparc64", ver:"2.6.15-55.81", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-386", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-generic", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-hppa32", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-hppa64", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-itanium", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-lpia", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-lpiacompat", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-mckinley", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-openvz", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-powerpc-smp", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-powerpc", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-powerpc64-smp", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-rt", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-server", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-sparc64-smp", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-sparc64", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-virtual", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-26-xen", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-2.6.24-26-sparc64-di", ver:"2.6.24-26.64", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-16-generic", ver:"2.6.27-16.44", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-16-server", ver:"2.6.27-16.44", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-16-virtual", ver:"2.6.27-16.44", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-generic", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-imx51", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-iop32x", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-ixp4xx", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-lpia", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-server", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-versatile", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-17-virtual", ver:"2.6.28-17.58", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-386", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-generic-pae", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-generic", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-ia64", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-lpia", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-powerpc-smp", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-powerpc", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-powerpc64-smp", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-server", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-sparc64-smp", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-sparc64", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-16-virtual", ver:"2.6.31-16.52", rls:"UBUNTU9.10"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.852.1");
  script_cve_id("CVE-2009-1883", "CVE-2009-2584", "CVE-2009-2695", "CVE-2009-2698", "CVE-2009-2767", "CVE-2009-2846", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2903", "CVE-2009-2908", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3288", "CVE-2009-3290");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-852-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-852-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15' package(s) announced via the USN-852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Solar Designer discovered that the z90crypt driver did not correctly
check capabilities. A local attacker could exploit this to shut down
the device, leading to a denial of service. Only affected Ubuntu 6.06.
(CVE-2009-1883)

Michael Buesch discovered that the SGI GRU driver did not correctly check
the length when setting options. A local attacker could exploit this
to write to the kernel stack, leading to root privilege escalation or
a denial of service. Only affected Ubuntu 8.10 and 9.04. (CVE-2009-2584)

It was discovered that SELinux did not fully implement the mmap_min_addr
restrictions. A local attacker could exploit this to allocate the
NULL memory page which could lead to further attacks against kernel
NULL-dereference vulnerabilities. Ubuntu 6.06 was not affected.
(CVE-2009-2695)

Cagri Coltekin discovered that the UDP stack did not correctly handle
certain flags. A local user could send specially crafted commands and
traffic to gain root privileges or crash the systeam, leading to a denial
of service. Only affected Ubuntu 6.06. (CVE-2009-2698)

Hiroshi Shimamoto discovered that monotonic timers did not correctly
validate parameters. A local user could make a specially crafted timer
request to gain root privileges or crash the system, leading to a denial
of service. Only affected Ubuntu 9.04. (CVE-2009-2767)

Michael Buesch discovered that the HPPA ISA EEPROM driver did not
correctly validate positions. A local user could make a specially crafted
request to gain root privileges or crash the system, leading to a denial
of service. (CVE-2009-2846)

Ulrich Drepper discovered that kernel signal stacks were not being
correctly padded on 64-bit systems. A local attacker could send specially
crafted calls to expose 4 bytes of kernel stack memory, leading to a
loss of privacy. (CVE-2009-2847)

Jens Rosenboom discovered that the clone method did not correctly clear
certain fields. A local attacker could exploit this to gain privileges
or crash the system, leading to a denial of service. (CVE-2009-2848)

It was discovered that the MD driver did not check certain sysfs files.
A local attacker with write access to /sys could exploit this to cause
a system crash, leading to a denial of service. Ubuntu 6.06 was not
affected. (CVE-2009-2849)

Mark Smith discovered that the AppleTalk stack did not correctly
manage memory. A remote attacker could send specially crafted traffic
to cause the system to consume all available memory, leading to a denial
of service. (CVE-2009-2903)

Loic Minier discovered that eCryptfs did not correctly handle writing
to certain deleted files. A local attacker could exploit this to gain
root privileges or crash the system, leading to a denial of service.
Ubuntu 6.06 was not affected. (CVE-2009-2908)

It was discovered that the LLC, AppleTalk, IR, EConet, Netrom, and
ROSE network stacks did not correctly initialize their data structures.
A local ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-386", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-686", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-generic", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-k8", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-server", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-amd64-xeon", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa32-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa32", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa64-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-hppa64", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-itanium-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-itanium", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-k7", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-mckinley-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-mckinley", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-powerpc-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-powerpc", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-powerpc64-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-server-bigiron", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-server", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-sparc64-smp", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-55-sparc64", ver:"2.6.15-55.80", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-386", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-generic", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-hppa32", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-hppa64", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-itanium", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-lpia", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-lpiacompat", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-mckinley", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-openvz", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-powerpc-smp", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-powerpc", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-powerpc64-smp", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-rt", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-server", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-sparc64-smp", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-sparc64", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-virtual", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-25-xen", ver:"2.6.24-25.63", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-15-generic", ver:"2.6.27-15.43", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-15-server", ver:"2.6.27-15.43", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-15-virtual", ver:"2.6.27-15.43", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-generic", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-imx51", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-iop32x", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-ixp4xx", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-lpia", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-server", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-versatile", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-16-virtual", ver:"2.6.28-16.55", rls:"UBUNTU9.04"))) {
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

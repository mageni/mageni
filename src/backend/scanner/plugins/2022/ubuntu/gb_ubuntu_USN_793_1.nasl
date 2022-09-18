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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.793.1");
  script_cve_id("CVE-2009-1072", "CVE-2009-1184", "CVE-2009-1192", "CVE-2009-1242", "CVE-2009-1265", "CVE-2009-1336", "CVE-2009-1337", "CVE-2009-1338", "CVE-2009-1360", "CVE-2009-1385", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1914", "CVE-2009-1961");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-793-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-793-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-793-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15' package(s) announced via the USN-793-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Igor Zhbanov discovered that NFS clients were able to create device nodes
even when root_squash was enabled. An authenticated remote attacker
could create device nodes with open permissions, leading to a loss of
privacy or escalation of privileges. Only Ubuntu 8.10 and 9.04 were
affected. (CVE-2009-1072)

Dan Carpenter discovered that SELinux did not correctly handle
certain network checks when running with compat_net=1. A local
attacker could exploit this to bypass network checks. Default Ubuntu
installations do not enable SELinux, and only Ubuntu 8.10 and 9.04 were
affected. (CVE-2009-1184)

Shaohua Li discovered that memory was not correctly initialized in the
AGP subsystem. A local attacker could potentially read kernel memory,
leading to a loss of privacy. (CVE-2009-1192)

Benjamin Gilbert discovered that the VMX implementation of KVM did
not correctly handle certain registers. An attacker in a guest VM
could exploit this to cause a host system crash, leading to a denial
of service. This only affected 32bit hosts. Ubuntu 6.06 was not
affected. (CVE-2009-1242)

Thomas Pollet discovered that the Amateur Radio X.25 Packet Layer Protocol
did not correctly validate certain fields. A remote attacker could exploit
this to read kernel memory, leading to a loss of privacy. (CVE-2009-1265)

Trond Myklebust discovered that NFS did not correctly handle certain
long filenames. An authenticated remote attacker could exploit this to
cause a system crash, leading to a denial of service. Only Ubuntu 6.06
was affected. (CVE-2009-1336)

Oleg Nesterov discovered that the kernel did not correctly handle
CAP_KILL. A local user could exploit this to send signals to arbitrary
processes, leading to a denial of service. (CVE-2009-1337)

Daniel Hokka Zakrisson discovered that signal handling was not correctly
limited to process namespaces. A local user could bypass namespace
restrictions, possibly leading to a denial of service. Only Ubuntu 8.04
was affected. (CVE-2009-1338)

Pavel Emelyanov discovered that network namespace support for IPv6 was
not correctly handled. A remote attacker could send specially crafted
IPv6 traffic that would cause a system crash, leading to a denial of
service. Only Ubuntu 8.10 and 9.04 were affected. (CVE-2009-1360)

Neil Horman discovered that the e1000 network driver did not correctly
validate certain fields. A remote attacker could send a specially
crafted packet that would cause a system crash, leading to a denial of
service. (CVE-2009-1385)

Pavan Naregundi discovered that CIFS did not correctly check lengths
when handling certain mount requests. A remote attacker could send
specially crafted traffic to cause a system crash, leading to a denial
of service. (CVE-2009-1439)

Simon Vallet and Frank Filz discovered that execute permissions were
not correctly handled by NFSv4. A local user could bypass permissions
and run restricted programs, possibly leading to ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-386", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-686", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-generic", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-k8", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-server", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-xeon", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa32-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa32", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa64-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa64", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-itanium-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-itanium", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-k7", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-mckinley-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-mckinley", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc64-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-server-bigiron", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-server", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-sparc64-smp", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-sparc64", ver:"2.6.15-54.77", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-386", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-generic", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-hppa32", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-hppa64", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-itanium", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-lpia", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-lpiacompat", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-mckinley", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-openvz", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-powerpc-smp", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-powerpc", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-powerpc64-smp", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-rt", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-server", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-sparc64-smp", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-sparc64", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-virtual", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-24-xen", ver:"2.6.24-24.55", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-14-generic", ver:"2.6.27-14.35", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-14-server", ver:"2.6.27-14.35", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-14-virtual", ver:"2.6.27-14.35", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-generic", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-imx51", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-iop32x", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-ixp4xx", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-lpia", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-server", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-versatile", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.28-13-virtual", ver:"2.6.28-13.45", rls:"UBUNTU9.04"))) {
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

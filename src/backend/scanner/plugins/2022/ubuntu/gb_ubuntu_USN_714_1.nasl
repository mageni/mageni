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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.714.1");
  script_cve_id("CVE-2008-5079", "CVE-2008-5134", "CVE-2008-5182", "CVE-2008-5300", "CVE-2008-5700", "CVE-2008-5702", "CVE-2008-5713");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-714-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-714-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15, linux-source-2.6.22' package(s) announced via the USN-714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hugo Dias discovered that the ATM subsystem did not correctly manage socket
counts. A local attacker could exploit this to cause a system hang, leading
to a denial of service. (CVE-2008-5079)

It was discovered that the libertas wireless driver did not correctly
handle beacon and probe responses. A physically near-by attacker could
generate specially crafted wireless network traffic and cause a denial of
service. Ubuntu 6.06 was not affected. (CVE-2008-5134)

It was discovered that the inotify subsystem contained watch removal race
conditions. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2008-5182)

Dann Frazier discovered that in certain situations sendmsg did not
correctly release allocated memory. A local attacker could exploit this to
force the system to run out of free memory, leading to a denial of service.
Ubuntu 6.06 was not affected. (CVE-2008-5300)

It was discovered that the ATA subsystem did not correctly set timeouts. A
local attacker could exploit this to cause a system hang, leading to a
denial of service. (CVE-2008-5700)

It was discovered that the ib700 watchdog timer did not correctly check
buffer sizes. A local attacker could send a specially crafted ioctl to the
device to cause a system crash, leading to a denial of service.
(CVE-2008-5702)

It was discovered that in certain situations the network scheduler did not
correctly handle very large levels of traffic. A local attacker could
produce a high volume of UDP traffic resulting in a system hang, leading to
a denial of service. Ubuntu 8.04 was not affected. (CVE-2008-5713)");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15, linux-source-2.6.22' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-386", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-686", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-amd64-generic", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-amd64-k8", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-amd64-server", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-amd64-xeon", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-hppa32-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-hppa32", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-hppa64-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-hppa64", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-itanium-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-itanium", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-k7", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-mckinley-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-mckinley", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-powerpc-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-powerpc", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-powerpc64-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-server-bigiron", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-server", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-sparc64-smp", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-53-sparc64", ver:"2.6.15-53.75", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-386", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-cell", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-generic", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-hppa32", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-hppa64", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-itanium", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-lpia", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-lpiacompat", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-mckinley", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-powerpc-smp", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-powerpc", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-powerpc64-smp", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-rt", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-server", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-sparc64-smp", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-sparc64", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-ume", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-virtual", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-xen", ver:"2.6.22-16.61", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-386", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-generic", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-hppa32", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-hppa64", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-itanium", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-lpia", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-lpiacompat", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-mckinley", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-openvz", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-powerpc-smp", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-powerpc", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-powerpc64-smp", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-rt", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-server", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-sparc64-smp", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-sparc64", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-virtual", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-xen", ver:"2.6.24-23.48", rls:"UBUNTU8.04 LTS"))) {
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

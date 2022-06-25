# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844503");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2019-19947", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-10732", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-11935", "CVE-2020-13974", "CVE-2019-12380");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-23 03:01:17 +0000 (Thu, 23 Jul 2020)");
  script_name("Ubuntu: Security Advisory for linux (USN-4427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"USN", value:"4427-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005519.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4427-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Kvaser CAN/USB driver in the Linux kernel did
not properly initialize memory in certain situations. A local attacker
could possibly use this to expose sensitive information (kernel memory).
(CVE-2019-19947)

Chuhong Yuan discovered that go7007 USB audio device driver in the Linux
kernel did not properly deallocate memory in some failure conditions. A
physically proximate attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2019-20810)

Jason A. Donenfeld discovered that the ACPI implementation in the Linux
kernel did not properly restrict loading SSDT code from an EFI variable. A
privileged attacker could use this to bypass Secure Boot lockdown
restrictions and execute arbitrary code in the kernel. (CVE-2019-20908)

It was discovered that the elf handling code in the Linux kernel did not
initialize memory before using it in certain situations. A local attacker
could use this to possibly expose sensitive information (kernel memory).
(CVE-2020-10732)

It was discovered that the Linux kernel did not correctly apply Speculative
Store Bypass Disable (SSBD) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10766)

It was discovered that the Linux kernel did not correctly apply Indirect
Branch Predictor Barrier (IBPB) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10767)

It was discovered that the Linux kernel could incorrectly enable indirect
branch speculation after it has been disabled for a process via a prctl()
call. A local attacker could possibly use this to expose sensitive
information. (CVE-2020-10768)

Mauricio Faria de Oliveira discovered that the aufs implementation in the
Linux kernel improperly managed inode reference counts in the
vfsub_dentry_open() method. A local attacker could use this vulnerability
to cause a denial of service. (CVE-2020-11935)

It was discovered that the Virtual Terminal keyboard driver in the Linux
kernel contained an integer overflow. A local attacker could possibly use
this to have a unspecified impact. (CVE-2020-13974)

It was discovered that the efi subsystem in the Linux kernel did not handle
memory allocation failures during early boot in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-12380)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1077-kvm", ver:"4.4.0-1077.84", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1111-aws", ver:"4.4.0-1111.123", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1136-raspi2", ver:"4.4.0-1136.145", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1140-snapdragon", ver:"4.4.0-1140.148", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-generic", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-generic-lpae", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-lowlatency", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-powerpc-e500mc", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-powerpc-smp", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-powerpc64-emb", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-186-powerpc64-smp", ver:"4.4.0-186.216", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1111.116", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1077.75", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1136.136", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.4.0.1140.132", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.186.192", rls:"UBUNTU16.04 LTS"))) {
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
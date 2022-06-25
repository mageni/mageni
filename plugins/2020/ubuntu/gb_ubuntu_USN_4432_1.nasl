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
  script_oid("1.3.6.1.4.1.25623.1.0.844519");
  script_version("2020-08-07T07:29:19+0000");
  script_cve_id("CVE-2020-10713", "CVE-2020-15706", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-14308", "CVE-2020-15705", "CVE-2020-15707");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-07 10:04:11 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-30 03:00:51 +0000 (Thu, 30 Jul 2020)");
  script_name("Ubuntu: Security Advisory for grub2 (USN-4432-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"USN", value:"4432-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005538.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2'
  package(s) announced via the USN-4432-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesse Michael and Mickey Shkatov discovered that the configuration parser
in GRUB2 did not properly exit when errors were discovered, resulting in
heap-based buffer overflows. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2020-10713)

Chris Coulson discovered that the GRUB2 function handling code did not
properly handle a function being redefined, leading to a use-after-free
vulnerability. A local attacker could use this to execute arbitrary code
and bypass UEFI Secure Boot restrictions. (CVE-2020-15706)

Chris Coulson discovered that multiple integer overflows existed in GRUB2
when handling certain filesystems or font files, leading to heap-based
buffer overflows. A local attacker could use these to execute arbitrary
code and bypass UEFI Secure Boot restrictions. (CVE-2020-14309,
CVE-2020-14310, CVE-2020-14311)

It was discovered that the memory allocator for GRUB2 did not validate
allocation size, resulting in multiple integer overflows and heap-based
buffer overflows when handling certain filesystems, PNG images or disk
metadata. A local attacker could use this to execute arbitrary code and
bypass UEFI Secure Boot restrictions. (CVE-2020-14308)

Mathieu Trudel-Lapierre discovered that in certain situations, GRUB2
failed to validate kernel signatures. A local attacker could use this
to bypass Secure Boot restrictions. (CVE-2020-15705)

Colin Watson and Chris Coulson discovered that an integer overflow
existed in GRUB2 when handling the initrd command, leading to a heap-based
buffer overflow. A local attacker could use this to execute arbitrary code
and bypass UEFI Secure Boot restrictions. (CVE-2020-15707)");

  script_tag(name:"affected", value:"'grub2' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.93.18+2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-bin", ver:"2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.93.18+2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-bin", ver:"2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia64-bin", ver:"2.02-2ubuntu8.16", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.66.26+2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-bin", ver:"2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.66.26+2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-bin", ver:"2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia64-bin", ver:"2.02~beta2-36ubuntu3.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.04-1ubuntu26.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.142.3+2.04-1ubuntu26.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-bin", ver:"2.04-1ubuntu26.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.04-1ubuntu26.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.142.3+2.04-1ubuntu26.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-bin", ver:"2.04-1ubuntu26.1", rls:"UBUNTU20.04 LTS"))) {
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
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0315");
  script_cve_id("CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-14372", "CVE-2020-15705", "CVE-2020-15706", "CVE-2020-15707", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0315");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0315.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27018");
  script_xref(name:"URL", value:"https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html");
  script_xref(name:"URL", value:"https://lists.gnu.org/archive/html/grub-devel/2021-06/msg00022.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SPZHLZ3UEVV7HQ6ETAHB7NRBRTPLHCNF/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XXPYL42MSKRB4D7LRFMW7PBGGLKSJKPS/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4992-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the MGASA-2021-0315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"All CVEs below are against the SecureBoot functionality in GRUB2.
We do not ship this as part of Mageia. Therefore, we ship an updated grub2
package to 2.06 for Mageia 8 fixing upstream bugfixes.

A flaw was found in grub2, prior to version 2.06. An attacker may use the
GRUB 2 flaw to hijack and tamper the GRUB verification process. This flaw also
allows the bypass of Secure Boot protections. In order to load an untrusted or
modified kernel, an attacker would first need to establish access to the system
such as gaining physical access, obtain the ability to alter a
pxe-boot network, or have remote access to a networked system with root access.
With this access, an attacker could then craft a string to cause a buffer
overflow by injecting a malicious payload that leads to arbitrary code execution
within GRUB. The highest threat from this vulnerability is to data
confidentiality and integrity as well as system availability (CVE-2020-10713).

In grub2 versions before 2.06 the grub memory allocator doesn't check for
possible arithmetic overflows on the requested allocation size. This leads the
function to return invalid memory allocations which can be further used to cause
possible integrity, confidentiality and availability impacts during the boot
process (CVE-2020-14308).

There's an issue with grub2 in all versions before 2.06 when handling squashfs
filesystems containing a symbolic link with name length of UINT32 bytes in size.
The name size leads to an arithmetic overflow leading to a zero-size allocation
further causing a heap-based buffer overflow with attacker controlled data
(CVE-2020-14309).

There is an issue on grub2 before version 2.06 at function
read_section_as_string(). It expects a font name to be at max UINT32_MAX - 1
length in bytes but it doesn't verify it before proceed with buffer allocation
to read the value from the font value. An attacker may leverage that by
crafting a malicious font file which has a name with UINT32_MAX, leading to
read_section_as_string() to an arithmetic overflow, zero-sized allocation and
further heap-based buffer overflow (CVE-2020-14310).

There is an issue with grub2 before version 2.06 while handling symlink on ext
filesystems. A filesystem containing a symbolic link with an inode size of
UINT32_MAX causes an arithmetic overflow leading to a zero-sized memory
allocation with subsequent heap-based buffer overflow (CVE-2020-14311).

A flaw was found in grub2 in versions prior to 2.06, where it incorrectly
enables the usage of the ACPI command when Secure Boot is enabled. This flaw
allows an attacker with privileged access to craft a Secondary System Description
Table (SSDT) containing code to overwrite the Linux kernel lockdown variable
content directly into memory. The table is further loaded and executed by the
kernel, defeating its Secure Boot lockdown and allowing the attacker to load
unsigned code. The highest threat from ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grub2' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.06~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.06~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu", rpm:"grub2-emu~2.06~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu-modules", rpm:"grub2-emu-modules~2.06~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-mageia-theme", rpm:"grub2-mageia-theme~2.06~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-uboot", rpm:"grub2-uboot~2.06~1.1.mga8", rls:"MAGEIA8"))) {
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

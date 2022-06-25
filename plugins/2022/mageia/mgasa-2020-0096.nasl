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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0096");
  script_cve_id("CVE-2018-11243", "CVE-2019-1010048", "CVE-2019-20021", "CVE-2019-20051", "CVE-2019-20053");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-03 03:15:00 +0000 (Mon, 03 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0096");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0096.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26172");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2020-02/msg00012.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2020-02/msg00006.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/D7XU42G6MUQQXHWRP7DCF2JSIBOJ5GOO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucl, upx' package(s) announced via the MGASA-2020-0096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

PackLinuxElf64::unpack in p_lx_elf.cpp in UPX 3.95 allows remote attackers
to cause a denial of service (double free), limit the ability of a malware
scanner to operate on the entire original data, or possibly have
 unspecified other impact via a crafted file. (CVE-2018-11243)

A heap-based buffer over-read was discovered in canUnpack in p_mach.cpp in
UPX 3.95 via a crafted Mach-O file. (CVE-2019-20021)

A floating-point exception was discovered in PackLinuxElf::elf_hash in
p_lx_elf.cpp in UPX 3.95. The vulnerability causes an application crash,
which leads to denial of service. (CVE-2019-20051)

An invalid memory address dereference was discovered in the canUnpack
function in p_mach.cpp in UPX 3.95 via a crafted Mach-O file.
(CVE-2019-20053)

A denial of service in PackLinuxElf32::PackLinuxElf32help1().
(CVE-2019-1010048)");

  script_tag(name:"affected", value:"'ucl, upx' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ucl-devel", rpm:"lib64ucl-devel~1.03~16.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ucl1", rpm:"lib64ucl1~1.03~16.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libucl-devel", rpm:"libucl-devel~1.03~16.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libucl1", rpm:"libucl1~1.03~16.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucl", rpm:"ucl~1.03~16.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"upx", rpm:"upx~3.96~1.mga7", rls:"MAGEIA7"))) {
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

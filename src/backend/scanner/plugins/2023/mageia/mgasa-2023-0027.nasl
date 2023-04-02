# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0027");
  script_cve_id("CVE-2021-31439", "CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122", "CVE-2022-23123", "CVE-2022-23124", "CVE-2022-23125", "CVE-2022-45188");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 12:48:00 +0000 (Thu, 27 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2023-0027)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0027");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0027.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31255");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013205.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010700.html");
  script_xref(name:"URL", value:"https://github.com/Netatalk/Netatalk/commit/895cecbeeae655b2793df6fcbf9df1c1bfbe285d");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netatalk' package(s) announced via the MGASA-2023-0027 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap overflow leading to arbitrary code execution. (CVE-2021-31439)
Buffer overflow leading to remote code execution (CVE-2022-0194)
Improper length validation leading to remote code execution
(CVE-2022-23121)
Buffer overflow leading to remote code execution (CVE-2022-23122)
Out-of-bounds read leading to information disclosure (CVE-2022-23123)
Out-of-bounds read leading to information disclosure (CVE-2022-23124)
Improper length validation leading to remote code execution
(CVE-2022-23125)
Heap-based buffer overflow in afp_getappl resulting in code execution via
a crafted .appl file (CVE-2022-45188)");

  script_tag(name:"affected", value:"'netatalk' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64netatalk-devel", rpm:"lib64netatalk-devel~3.1.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64netatalk18", rpm:"lib64netatalk18~3.1.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetatalk-devel", rpm:"libnetatalk-devel~3.1.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetatalk18", rpm:"libnetatalk18~3.1.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netatalk", rpm:"netatalk~3.1.14~1.1.mga8", rls:"MAGEIA8"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0316");
  script_cve_id("CVE-2021-3403", "CVE-2021-3404");
  script_tag(name:"creation_date", value:"2022-09-05 05:04:07 +0000 (Mon, 05 Sep 2022)");
  script_version("2022-09-05T05:04:07+0000");
  script_tag(name:"last_modification", value:"2022-09-05 05:04:07 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-10 20:22:00 +0000 (Wed, 10 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0316)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0316");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0316.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30735");
  script_xref(name:"URL", value:"https://github.com/Yeraze/ytnef/releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ytnef' package(s) announced via the MGASA-2022-0316 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ytnef 1.9.3, the TNEFSubjectHandler function in lib/ytnef.c allows
remote attackers to cause a denial-of-service (and potentially code
execution) due to a double free which can be triggered via a crafted file.
(CVE-2021-3403)
In ytnef 1.9.3, the SwapWord function in lib/ytnef.c allows remote
attackers to cause a denial-of-service (and potentially code execution)
due to a heap buffer overflow which can be triggered via a crafted file.
(CVE-2021-3404)");

  script_tag(name:"affected", value:"'ytnef' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ytnef-devel", rpm:"lib64ytnef-devel~2.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ytnef0", rpm:"lib64ytnef0~2.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libytnef-devel", rpm:"libytnef-devel~2.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libytnef0", rpm:"libytnef0~2.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ytnef", rpm:"ytnef~2.0~1.mga8", rls:"MAGEIA8"))) {
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

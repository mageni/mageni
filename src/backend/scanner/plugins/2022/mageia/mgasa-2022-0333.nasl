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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0333");
  script_cve_id("CVE-2022-35252");
  script_tag(name:"creation_date", value:"2022-09-19 05:11:13 +0000 (Mon, 19 Sep 2022)");
  script_version("2022-09-19T10:11:35+0000");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0333");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0333.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30794");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2022-35252.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TXSXGBF37COLVO73E7EGYA34POPEHESU/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2022-0333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Control code in cookie denial of service. (CVE-2022-35252)");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.74.0~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.74.0~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.74.0~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.74.0~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.74.0~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.74.0~1.8.mga8", rls:"MAGEIA8"))) {
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

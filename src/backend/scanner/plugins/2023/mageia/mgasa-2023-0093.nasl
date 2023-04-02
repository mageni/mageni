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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0093");
  script_cve_id("CVE-2020-21594", "CVE-2020-21595", "CVE-2020-21596", "CVE-2020-21597", "CVE-2020-21598", "CVE-2020-21599", "CVE-2020-21600", "CVE-2020-21601", "CVE-2020-21602", "CVE-2020-21603", "CVE-2020-21604", "CVE-2020-21605", "CVE-2020-21606", "CVE-2021-35452", "CVE-2021-36408", "CVE-2021-36409", "CVE-2021-36410", "CVE-2021-36411", "CVE-2022-1253", "CVE-2022-43235", "CVE-2022-43236", "CVE-2022-43237", "CVE-2022-43238", "CVE-2022-43239", "CVE-2022-43240", "CVE-2022-43241", "CVE-2022-43242", "CVE-2022-43243", "CVE-2022-43244", "CVE-2022-43245", "CVE-2022-43248", "CVE-2022-43249", "CVE-2022-43250", "CVE-2022-43252", "CVE-2022-43253", "CVE-2022-47655", "CVE-2022-47664", "CVE-2022-47665", "CVE-2023-24751", "CVE-2023-24752", "CVE-2023-24754", "CVE-2023-24755", "CVE-2023-24756", "CVE-2023-24757", "CVE-2023-24758", "CVE-2023-25221");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-14 17:52:00 +0000 (Thu, 14 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0093");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0093.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31289");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3240");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3280");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5346");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3352");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libde265' package(s) announced via the MGASA-2023-0093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libde265 has been updated to version 1.0.11 to fix many security issues.");

  script_tag(name:"affected", value:"'libde265' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64de265-devel", rpm:"lib64de265-devel~1.0.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64de265-devel", rpm:"lib64de265-devel~1.0.11~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64de265_0", rpm:"lib64de265_0~1.0.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64de265_0", rpm:"lib64de265_0~1.0.11~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libde265", rpm:"libde265~1.0.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libde265", rpm:"libde265~1.0.11~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libde265-devel", rpm:"libde265-devel~1.0.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libde265-devel", rpm:"libde265-devel~1.0.11~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libde265_0", rpm:"libde265_0~1.0.11~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libde265_0", rpm:"libde265_0~1.0.11~1.mga8.tainted", rls:"MAGEIA8"))) {
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

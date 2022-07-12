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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0355");
  script_cve_id("CVE-2014-4607");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-14 15:26:00 +0000 (Fri, 14 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0355)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0355");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0355.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13934");
  script_xref(name:"URL", value:"http://www.oberhumer.com/opensource/lzo/#news");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0290.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'harbour, harbour' package(s) announced via the MGASA-2014-0355 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in liblzo before 2.07 allows attackers to cause a
denial of service or possibly code execution in applications using
performing LZO decompression on a compressed payload from the attacker
(CVE-2014-4607).

The harbour is built with a bundled copy of minilzo, which is a part of
liblzo containing the vulnerable code. This update is patched to update
the bundled minilzo to version 2.8.");

  script_tag(name:"affected", value:"'harbour, harbour' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"harbour", rpm:"harbour~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harbour-bundle", rpm:"harbour-bundle~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harbour-hbide", rpm:"harbour-hbide~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-allegro3", rpm:"lib64harbour-allegro3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-cairo3", rpm:"lib64harbour-cairo3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-contrib3", rpm:"lib64harbour-contrib3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-cups3", rpm:"lib64harbour-cups3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-curl3", rpm:"lib64harbour-curl3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-firebird3", rpm:"lib64harbour-firebird3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-freeimage3", rpm:"lib64harbour-freeimage3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-gd3", rpm:"lib64harbour-gd3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-mysql3", rpm:"lib64harbour-mysql3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-odbc3", rpm:"lib64harbour-odbc3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-pgsql3", rpm:"lib64harbour-pgsql3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-qt3", rpm:"lib64harbour-qt3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour3", rpm:"lib64harbour3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-allegro3", rpm:"libharbour-allegro3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-cairo3", rpm:"libharbour-cairo3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-contrib3", rpm:"libharbour-contrib3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-cups3", rpm:"libharbour-cups3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-curl3", rpm:"libharbour-curl3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-firebird3", rpm:"libharbour-firebird3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-freeimage3", rpm:"libharbour-freeimage3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-gd3", rpm:"libharbour-gd3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-mysql3", rpm:"libharbour-mysql3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-odbc3", rpm:"libharbour-odbc3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-pgsql3", rpm:"libharbour-pgsql3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-qt3", rpm:"libharbour-qt3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour3", rpm:"libharbour3~3.2.0~0.18748_111.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"harbour", rpm:"harbour~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harbour-bundle", rpm:"harbour-bundle~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harbour-hbdbu", rpm:"harbour-hbdbu~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harbour-hbide", rpm:"harbour-hbide~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-allegro3", rpm:"lib64harbour-allegro3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-cairo3", rpm:"lib64harbour-cairo3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-contrib3", rpm:"lib64harbour-contrib3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-cups3", rpm:"lib64harbour-cups3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-curl3", rpm:"lib64harbour-curl3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-firebird3", rpm:"lib64harbour-firebird3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-freeimage3", rpm:"lib64harbour-freeimage3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-gd3", rpm:"lib64harbour-gd3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-mysql3", rpm:"lib64harbour-mysql3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-odbc3", rpm:"lib64harbour-odbc3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-pgsql3", rpm:"lib64harbour-pgsql3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour-qt3", rpm:"lib64harbour-qt3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64harbour3", rpm:"lib64harbour3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-allegro3", rpm:"libharbour-allegro3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-cairo3", rpm:"libharbour-cairo3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-contrib3", rpm:"libharbour-contrib3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-cups3", rpm:"libharbour-cups3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-curl3", rpm:"libharbour-curl3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-firebird3", rpm:"libharbour-firebird3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-freeimage3", rpm:"libharbour-freeimage3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-gd3", rpm:"libharbour-gd3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-mysql3", rpm:"libharbour-mysql3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-odbc3", rpm:"libharbour-odbc3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-pgsql3", rpm:"libharbour-pgsql3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour-qt3", rpm:"libharbour-qt3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharbour3", rpm:"libharbour3~3.2.0~1.18925.255.3.mga4", rls:"MAGEIA4"))) {
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

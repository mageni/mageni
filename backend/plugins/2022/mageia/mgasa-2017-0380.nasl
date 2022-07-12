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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0380");
  script_cve_id("CVE-2017-10140");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 18:15:00 +0000 (Wed, 15 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2017-0380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0380");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0380.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21203");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/08/12/1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4JKFB2V7HP5V4KCYKSXMTWUDWUWQOV3S/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'db48, db48, db53, db53' package(s) announced via the MGASA-2017-0380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that Berkeley DB reads the DB_CONFIG configuration file from the
current working directory by default. This happens when calling db_create()
with dbenv=NULL, or using the dbm_open() function (CVE-2017-10140).");

  script_tag(name:"affected", value:"'db48, db48, db53, db53' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"db48", rpm:"db48~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db48-utils", rpm:"db48-utils~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53", rpm:"db53~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53-utils", rpm:"db53-utils~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53_recover", rpm:"db53_recover~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db4.8", rpm:"lib64db4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db4.8-devel", rpm:"lib64db4.8-devel~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db4.8-static-devel", rpm:"lib64db4.8-static-devel~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3", rpm:"lib64db5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3-devel", rpm:"lib64db5.3-devel~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3-static-devel", rpm:"lib64db5.3-static-devel~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbcxx4.8", rpm:"lib64dbcxx4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbcxx5.3", rpm:"lib64dbcxx5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbjava5.3", rpm:"lib64dbjava5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss4.8", rpm:"lib64dbnss4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss4.8-devel", rpm:"lib64dbnss4.8-devel~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss5.3", rpm:"lib64dbnss5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss5.3-devel", rpm:"lib64dbnss5.3-devel~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbsql5.3", rpm:"lib64dbsql5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbtcl4.8", rpm:"lib64dbtcl4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbtcl5.3", rpm:"lib64dbtcl5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb4.8", rpm:"libdb4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb4.8-devel", rpm:"libdb4.8-devel~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb4.8-static-devel", rpm:"libdb4.8-static-devel~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3", rpm:"libdb5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3-devel", rpm:"libdb5.3-devel~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3-static-devel", rpm:"libdb5.3-static-devel~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbcxx4.8", rpm:"libdbcxx4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbcxx5.3", rpm:"libdbcxx5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbjava5.3", rpm:"libdbjava5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss4.8", rpm:"libdbnss4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss4.8-devel", rpm:"libdbnss4.8-devel~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss5.3", rpm:"libdbnss5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss5.3-devel", rpm:"libdbnss5.3-devel~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbsql5.3", rpm:"libdbsql5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbtcl4.8", rpm:"libdbtcl4.8~4.8.30~18.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbtcl5.3", rpm:"libdbtcl5.3~5.3.28~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"db48", rpm:"db48~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db48-utils", rpm:"db48-utils~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53", rpm:"db53~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53-utils", rpm:"db53-utils~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53_recover", rpm:"db53_recover~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db4.8", rpm:"lib64db4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db4.8-devel", rpm:"lib64db4.8-devel~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db4.8-static-devel", rpm:"lib64db4.8-static-devel~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3", rpm:"lib64db5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3-devel", rpm:"lib64db5.3-devel~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3-static-devel", rpm:"lib64db5.3-static-devel~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbcxx4.8", rpm:"lib64dbcxx4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbcxx5.3", rpm:"lib64dbcxx5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbjava5.3", rpm:"lib64dbjava5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss4.8", rpm:"lib64dbnss4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss4.8-devel", rpm:"lib64dbnss4.8-devel~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss5.3", rpm:"lib64dbnss5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbnss5.3-devel", rpm:"lib64dbnss5.3-devel~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbsql5.3", rpm:"lib64dbsql5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbtcl4.8", rpm:"lib64dbtcl4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbtcl5.3", rpm:"lib64dbtcl5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb4.8", rpm:"libdb4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb4.8-devel", rpm:"libdb4.8-devel~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb4.8-static-devel", rpm:"libdb4.8-static-devel~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3", rpm:"libdb5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3-devel", rpm:"libdb5.3-devel~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3-static-devel", rpm:"libdb5.3-static-devel~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbcxx4.8", rpm:"libdbcxx4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbcxx5.3", rpm:"libdbcxx5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbjava5.3", rpm:"libdbjava5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss4.8", rpm:"libdbnss4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss4.8-devel", rpm:"libdbnss4.8-devel~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss5.3", rpm:"libdbnss5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbnss5.3-devel", rpm:"libdbnss5.3-devel~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbsql5.3", rpm:"libdbsql5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbtcl4.8", rpm:"libdbtcl4.8~4.8.30~21.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbtcl5.3", rpm:"libdbtcl5.3~5.3.28~10.1.mga6", rls:"MAGEIA6"))) {
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

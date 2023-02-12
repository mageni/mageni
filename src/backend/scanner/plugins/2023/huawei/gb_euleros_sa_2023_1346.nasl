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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1346");
  script_cve_id("CVE-2021-43766", "CVE-2021-43767");
  script_tag(name:"creation_date", value:"2023-02-09 04:29:52 +0000 (Thu, 09 Feb 2023)");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 16:54:00 +0000 (Wed, 31 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for postgresql-10.5 (EulerOS-SA-2023-1346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1346");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1346");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'postgresql-10.5' package(s) announced via the EulerOS-SA-2023-1346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Odyssey passes to server unencrypted bytes from man-in-the-middle When Odyssey is configured to use certificate Common Name for client authentication, a man-in-the-middle attacker can inject arbitrary SQL queries when a connection is first established, despite the use of SSL certificate verification and encryption. This is similar to CVE-2021-23214 for PostgreSQL.(CVE-2021-43766)

Odyssey passes to client unencrypted bytes from man-in-the-middle When Odyssey storage is configured to use the PostgreSQL server using 'trust' authentication with a 'clientcert' requirement or to use 'cert' authentication, a man-in-the-middle attacker can inject false responses to the client's first few queries. Despite the use of SSL certificate verification and encryption, Odyssey will pass these results to client as if they originated from valid server. This is similar to CVE-2021-23222 for PostgreSQL.(CVE-2021-43767)");

  script_tag(name:"affected", value:"'postgresql-10.5' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~10.5~3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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

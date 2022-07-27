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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0095");
  script_cve_id("CVE-2013-5572", "CVE-2014-1682", "CVE-2014-1685");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-05-09 16:46:00 +0000 (Fri, 09 May 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0095");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0095.html");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-6721");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-7693");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-7703");
  script_xref(name:"URL", value:"http://www.zabbix.com/rn2.0.11.php");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12574");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix, zabbix' package(s) announced via the MGASA-2014-0095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated zabbix packages fix security vulnerabilities:

Zabbix before 2.0.11 allows remote authenticated users to discover the LDAP
bind password by leveraging management-console access and reading the
ldap_bind_password value in the HTML source code (CVE-2013-5572).

Zabbix before 2.0.11 allows switching users without proper credentials when
using HTTP authentication (CVE-2014-1682).

In Zabbix before 2.0.11, the admin user is able to update media for other
users (CVE-2014-1685).");

  script_tag(name:"affected", value:"'zabbix, zabbix' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-java", rpm:"zabbix-java~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-pgsql", rpm:"zabbix-proxy-pgsql~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite", rpm:"zabbix-proxy-sqlite~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-pgsql", rpm:"zabbix-server-pgsql~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-sqlite", rpm:"zabbix-server-sqlite~2.0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web", rpm:"zabbix-web~2.0.11~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-java", rpm:"zabbix-java~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-pgsql", rpm:"zabbix-proxy-pgsql~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite", rpm:"zabbix-proxy-sqlite~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-pgsql", rpm:"zabbix-server-pgsql~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-sqlite", rpm:"zabbix-server-sqlite~2.0.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web", rpm:"zabbix-web~2.0.11~1.mga4", rls:"MAGEIA4"))) {
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

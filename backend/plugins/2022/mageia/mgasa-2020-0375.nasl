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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0375");
  script_cve_id("CVE-2019-10162", "CVE-2019-10163", "CVE-2019-10203", "CVE-2020-17482");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 14:27:00 +0000 (Fri, 02 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0375)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0375");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0375.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24994");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27310");
  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/changelog/4.1.html#change-4.1.14");
  script_xref(name:"URL", value:"https://blog.powerdns.com/2019/08/01/security-notice-for-powerdnspostgres-users/");
  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2019-04.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2019-05.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2019-06.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2020-05.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns' package(s) announced via the MGASA-2020-0375 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause the server to exit by inserting a crafted record in a
MASTER type zone under their control. The issue is due to the fact that the
Authoritative Server will exit when it runs into a parsing error while looking
up the NS/A/AAAA records it is about to use for an outgoing notify
(CVE-2019-10162).

An issue has been found in PowerDNS Authoritative Server allowing a remote,
authorized master server to cause a high CPU load or even prevent any further
updates to any slave zone by sending a large number of NOTIFY messages. Note
that only servers configured as slaves are affected by this issue
(CVE-2019-10163).

An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause the server to exit by inserting a crafted record in a
MASTER type zone under their control. The issue is due to the fact that the
Authoritative Server will exit when it tries to store the notified serial in
the PostgreSQL database, if this serial cannot be represented in 31 bits
(CVE-2019-10203).

An issue has been found in PowerDNS Authoritative Server before 4.3.1 where an
authorized user with the ability to insert crafted records into a zone might be
able to leak the content of uninitialized memory. Such a user could be a
customer inserting data via a control panel, or somebody with access to the
REST API. Crafted records cannot be inserted via AXFR (CVE-2020-17482).

The pdns package has been updated to version 4.1.14, fixing these issues and
several other bugs. See the upstream changelog for details.

Also note that manual intervention is required to fix the CVE-2019-10203 issue
for those using PostgreSQL with pdns. See the upstream blog post for details.");

  script_tag(name:"affected", value:"'pdns' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~4.1.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geoip", rpm:"pdns-backend-geoip~4.1.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~4.1.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~4.1.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~4.1.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~4.1.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~4.1.14~1.mga7", rls:"MAGEIA7"))) {
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

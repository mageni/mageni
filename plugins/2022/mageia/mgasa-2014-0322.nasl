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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0322");
  script_cve_id("CVE-2014-2983", "CVE-2014-5019", "CVE-2014-5020", "CVE-2014-5021", "CVE-2014-5022");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 12:50:00 +0000 (Tue, 20 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2014-0322)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0322");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0322.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13271");
  script_xref(name:"URL", value:"https://drupal.org/SA-CORE-2014-002");
  script_xref(name:"URL", value:"https://drupal.org/SA-CORE-2014-003");
  script_xref(name:"URL", value:"https://drupal.org/drupal-7.27");
  script_xref(name:"URL", value:"https://drupal.org/drupal-7.27-release-notes");
  script_xref(name:"URL", value:"https://drupal.org/drupal-7.28");
  script_xref(name:"URL", value:"https://drupal.org/drupal-7.28-release-notes");
  script_xref(name:"URL", value:"https://drupal.org/drupal-7.29");
  script_xref(name:"URL", value:"https://drupal.org/drupal-7.29-release-notes");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2913");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2983");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal, drupal' package(s) announced via the MGASA-2014-0322 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure vulnerability was discovered in Drupal before 7.27.
When pages are cached for anonymous users, form state may leak between
anonymous users. Sensitive or private information recorded for one anonymous
user could thus be disclosed to other users interacting with the same form at
the same time (CVE-2014-2983).

Multiple security issues in Drupal before 7.29, including a denial of service
issue, an access bypass issue in the File module, and multiple cross-site
scripting issues (CVE-2014-5019, CVE-2014-5020, CVE-2014-5021, CVE-2014-5022).

Drupal has been updated to version 7.29, fixing this and other bugs.");

  script_tag(name:"affected", value:"'drupal, drupal' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.29~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.29~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.29~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.29~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.29~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.29~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.29~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.29~1.mga4", rls:"MAGEIA4"))) {
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

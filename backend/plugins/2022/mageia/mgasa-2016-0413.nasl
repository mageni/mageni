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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0413");
  script_cve_id("CVE-2016-9449", "CVE-2016-9451");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0413)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0413");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0413.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19812");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-005");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.45");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.45-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.46");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.46-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.47");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.47-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.48");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.48-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.49");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.49-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.50");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.50-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.51");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.51-release-notes");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.52");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.52-release-notes");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/11/18/16");
  script_xref(name:"URL", value:"https://lwn.net/Vulnerabilities/707038/");
  script_xref(name:"URL", value:"https://lwn.net/Vulnerabilities/707041/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal' package(s) announced via the MGASA-2016-0413 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Inconsistent name for term access query, information on taxonomy terms
might have been disclosed to unprivileged users (CVE-2016-9449).

Confirmation forms allow external URLs to be injected (CVE-2016-9451).");

  script_tag(name:"affected", value:"'drupal' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.52~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.52~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.52~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.52~1.mga5", rls:"MAGEIA5"))) {
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

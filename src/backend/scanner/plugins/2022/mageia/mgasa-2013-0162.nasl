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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0162");
  script_cve_id("CVE-2013-2079", "CVE-2013-2080", "CVE-2013-2081", "CVE-2013-2082", "CVE-2013-2083");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:52:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2013-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0162");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0162.html");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228930");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228931");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228933");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228934");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228935");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.4.4_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228536");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2013-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The assignment module in Moodle before 2.4.4 was not checking capabilities
for users downloading all assignments as a zip (CVE-2013-2079).

The Gradebook's Overview report in Moodle before 2.4.4 was showing grade
totals that may have incorrectly included hidden grades (CVE-2013-2080).

When registering a site on a hub (not Moodle.net) site in Moodle before
2.4.4, information was being sent to the hub regardless of settings chosen
(CVE-2013-2081).

There was no check of permissions for viewing comments on blog posts in
Moodle before 2.4.4 (CVE-2013-2082).

Form elements named using a specific naming scheme were not being filtered
correctly in Moodle before 2.4.4 (CVE-2013-2083).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.4~1.1.mga3", rls:"MAGEIA3"))) {
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

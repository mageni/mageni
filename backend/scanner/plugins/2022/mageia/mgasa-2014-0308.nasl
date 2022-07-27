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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0308");
  script_cve_id("CVE-2014-3541", "CVE-2014-3542", "CVE-2014-3543", "CVE-2014-3544", "CVE-2014-3545", "CVE-2014-3546", "CVE-2014-3547", "CVE-2014-3548", "CVE-2014-3551", "CVE-2014-3553");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:54:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0308");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0308.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13759");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264262");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264263");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264264");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264265");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264266");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264267");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264268");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264269");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264270");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264273");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.6.4_release_notes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle, moodle' package(s) announced via the MGASA-2014-0308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.6.4, serialised data passed by repositories could
potentially contain objects defined by add-ons that could include executable
code (CVE-2014-3541).

In Moodle before 2.6.4, it was possible for manipulated XML files passed from
LTI servers to be interpreted by Moodle to allow access to server-side files
(CVE-2014-3542).

In Moodle before 2.6.4, it was possible for manipulated XML files to be
uploaded to the IMSCC course format or the IMSCP resource to allow access to
server-side files (CVE-2014-3543).

In Moodle before 2.6.4, filtering of the Skype profile field was not removing
potentially harmful code (CVE-2014-3544).

In Moodle before 2.6.4, it was possible to inject code into Calculated
questions that would be executed on the server (CVE-2014-3545).

In Moodle before 2.6.4, it was possible to get limited user information,
such as user name and courses, by manipulating the URL of profile and notes
pages (CVE-2014-3546).

In Moodle before 2.6.4, the details of badges from external sources were not
being filtered (CVE-2014-3547).

In Moodle before 2.6.4, content of exception dialogues presented from AJAX
calls was not being escaped before being presented to users (CVE-2014-3548).

In Moodle before 2.6.4, fields in rubrics were not being correctly filtered
(CVE-2014-3551).

In Moodle before 2.6.4, forum was allowing users who were members of more
than one group to post to all groups without the capability to access all
groups (CVE-2014-3553).

The moodle package has been updated to version 2.6.4, to fix these issues
and other bugs.");

  script_tag(name:"affected", value:"'moodle, moodle' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.4~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.4~1.mga4", rls:"MAGEIA4"))) {
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

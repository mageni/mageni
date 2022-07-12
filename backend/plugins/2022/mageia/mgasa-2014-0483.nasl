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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0483");
  script_cve_id("CVE-2014-7830", "CVE-2014-7832", "CVE-2014-7833", "CVE-2014-7834", "CVE-2014-7835", "CVE-2014-7836", "CVE-2014-7837", "CVE-2014-7838", "CVE-2014-7845", "CVE-2014-7846", "CVE-2014-7847", "CVE-2014-7848");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:54:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0483");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0483.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14538");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275146");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275147");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275152");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275154");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275155");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275157");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275158");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275159");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275160");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275161");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275162");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275163");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275164");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=275165");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.6.6_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=274730");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle, moodle' package(s) announced via the MGASA-2014-0483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.6.5, without forcing encoding, it was possible that UTF7
characters could be used to force cross-site scripts to AJAX scripts
(although this is unlikely on modern browsers and on most Moodle pages)
(MSA-14-0035).

In Moodle before 2.6.5, an XSS issue through $searchcourse in
mod/feedback/mapcourse.php, due to the last search string in the Feedback
module not being escaped in the search input field (CVE-2014-7830).

In Moodle before 2.6.5, the word list for temporary password generation was
short, therefore the pool of possible passwords was not big enough
(CVE-2014-7845).

In Moodle before 2.6.5, capability checks in the LTI module only checked
access to the course and not to the activity (CVE-2014-7832).

In Moodle before 2.6.5, group-level entries in Database activity module
became visible to users in other groups after being edited by a teacher
(CVE-2014-7833).

In Moodle before 2.6.5, unprivileged users could access the list of
available tags in the system (CVE-2014-7846).

In Moodle before 2.6.5, the script used to geo-map IP addresses was
available to unauthenticated users increasing server load when used by
other parties (CVE-2014-7847).

In Moodle before 2.6.5, when using the web service function for Forum
discussions, group permissions were not checked (CVE-2014-7834).

In Moodle before 2.6.5, by directly accessing an internal file, an
unauthenticated user can be shown an error message containing the file
system path of the Moodle install (CVE-2014-7848).

In Moodle before 2.6.5, if web service with file upload function was
available, user could upload XSS file to his profile picture area
(CVE-2014-7835).

In Moodle before 2.6.5, two files in the LTI module lacked a session key
check, potentially allowing cross-site request forgery (CVE-2014-7836).

In Moodle before 2.6.5, by tweaking URLs, users who were able to delete
pages in at least one Wiki activity in the course were able to delete pages
in other Wiki pages in the same course (CVE-2014-7837).

In Moodle before 2.6.5, set tracking script in the Forum module lacked a
session key check, potentially allowing cross-site request forgery
(CVE-2014-7838).

In Moodle before 2.6.5, session key check was missing on return page in
module LTI allowing attacker to include arbitrary message in URL query
string (MSA-14-0049).");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.6~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.6~1.mga4", rls:"MAGEIA4"))) {
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

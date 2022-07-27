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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0160");
  script_cve_id("CVE-2013-7341", "CVE-2014-0122", "CVE-2014-0123", "CVE-2014-0124", "CVE-2014-0125", "CVE-2014-0126", "CVE-2014-0127", "CVE-2014-2571");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:52:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0160");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0160.html");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256416");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256417");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256418");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256419");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256420");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256421");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256422");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=256423");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.4.9_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=255903");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13005");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle, moodle' package(s) announced via the MGASA-2014-0160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

In Moodle before 2.4.9, question strings were not being filtered correctly
possibly allowing cross site scripting, as quiz_question_tostring can cause
invalid HTML (CVE-2014-2571).

Feedback Availability dates not honored in complete.php in Moodle before
2.4.9, therefore it was possible to start a Feedback activity while it was
supposed to be closed (CVE-2014-0127).

Broken access control vulnerability in Moodle before 2.4.9 with
/mod/chat/chat_ajax.php, where capabilities to chat were being checked at the
start of a chat, but not during, so changes were not effective immediately
(CVE-2014-0122).

In Moodle before 2.4.9, there were missing access checks on Wiki pages
allowing students to see pages of other students' individual wikis, through
the Recent activity block (CVE-2014-0123).

In Moodle before 2.4.9, cross site scripting was possible with Flowplayer
(CVE-2013-7341).

In Moodle before 2.4.9, Forum and Quiz were showing users' email addresses
when settings were supposed to be preventing this (CVE-2014-0124).

In Moodle before 2.4.9, alias links to items in an Alfresco repository were
provided with information that would allow someone to impersonate the file
owner in Alfresco (CVE-2014-0125).

Cross Site Request Forgery in Moodle before 2.4.9 in
enrol/imsenterprise/importnow.php, due to inadequate session checking when
triggering the import of IMS Enterprise identities (CVE-2014-0126).");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.9~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.9~1.mga4", rls:"MAGEIA4"))) {
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

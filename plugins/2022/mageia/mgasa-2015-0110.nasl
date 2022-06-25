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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0110");
  script_cve_id("CVE-2015-2266", "CVE-2015-2267", "CVE-2015-2268", "CVE-2015-2269", "CVE-2015-2270", "CVE-2015-2271", "CVE-2015-2272", "CVE-2015-2273");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:54:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0110)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0110");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0110.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15501");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307380");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307381");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307382");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307383");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307384");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307385");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307386");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=307387");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.6.10_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=305077");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2015-0110 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

In Moodle before 2.6.9, by modifying URL a logged in user can view the list
of another user's contacts, number of unread messages and list of their
courses (CVE-2015-2266).

In Moodle before 2.6.9, authentication in mdeploy can be bypassed. It is
theoretically possible to extract files anywhere on the system where the web
server has write access. The attacking user must know details about the
system and already have significant permissions on the site (CVE-2015-2267).

In Moodle before 2.6.9, a non-optimal regular expression in the 'Convert
links to URLs' filter could be exploited to create extra server load or make
particular pages unavailable (CVE-2015-2268).

In Moodle before 2.6.9, it is possible to create HTML injection through
blocks with configurable titles, however this could only be exploited by
users who are already marked as XSS-trusted (CVE-2015-2269).

In Moodle before 2.6.9, for the custom themes that use blocks regions in the
base layout the blocks for inaccessible courses could be displayed together
with sensitive course-related information. Most of the themes, including all
standard Moodle themes, are not affected (CVE-2015-2270).

In Moodle before 2.6.9, users without proper permission are able to mark
tags as inappropriate. Since this capability is given to authenticated users
by default, this is not an issue for most sites (CVE-2015-2271).

In Moodle before 2.6.9, even when user's password is forced to be changed on
login, user could still use it for authentication in order to create the web
service token and therefore extend the life of the temporary password via
web services (CVE-2015-2272).

In Moodle before 2.6.9, Quiz statistics report did not properly escape
student responses and could be used for XSS attack (CVE-2015-2273).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.10~1.mga4", rls:"MAGEIA4"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0032");
  script_cve_id("CVE-2015-0211", "CVE-2015-0212", "CVE-2015-0213", "CVE-2015-0214", "CVE-2015-0215", "CVE-2015-0217", "CVE-2015-0218");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 14:54:00 +0000 (Tue, 01 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0032)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0032");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0032.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15084");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278611");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278612");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278613");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278614");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278615");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278617");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278618");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.6.7_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=278176");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2015-0032 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

In Moodle before 2.6.7, absence of a capability check in AJAX backend script
in the LTI module could allow any enrolled user to search the list of
registered tools (CVE-2015-0211).

In Moodle before 2.6.7, the course summary on course request pending approval
page was displayed to the manager unescaped and could be used for XSS attack
(CVE-2015-0212).

In Moodle before 2.6.7, two files in the Glossary module lacked a session key
check potentially allowing cross-site request forgery (CVE-2015-0213).

In Moodle before 2.6.7, through web-services it was possible to access
messaging-related functions such as people search even if messaging is
disabled on the site (CVE-2015-0214).

In Moodle before 2.6.7, through web-services it was possible to get
information about calendar events which user did not have enough permissions
to see (CVE-2015-0215).

In Moodle before 2.6.7, non-optimal regular expression in the multimedia
filter could be exploited to create extra server load or make particular page
unavailable, resulting in a denial of service (CVE-2015-0217).

In Moodle before 2.6.7, it was possible to forge a request to logout users
even when not authenticated through Shibboleth (CVE-2015-0218).");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.7~1.mga4", rls:"MAGEIA4"))) {
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

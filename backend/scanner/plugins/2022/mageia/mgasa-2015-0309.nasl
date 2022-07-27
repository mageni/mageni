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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0309");
  script_cve_id("CVE-2015-2213", "CVE-2015-5730", "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5733", "CVE-2015-5734");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0309");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0309.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16531");
  script_xref(name:"URL", value:"http://codex.wordpress.org/Version_3.9.8");
  script_xref(name:"URL", value:"https://wordpress.org/news/2015/08/wordpress-4-2-4-security-and-maintenance-release/");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/08/04/7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress' package(s) announced via the MGASA-2015-0309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The wordpress package has been updated to version 3.9.8, fixing three
cross-site scripting issues (CVE-2015-5732, CVE-2015-5733, CVE-2015-5734),
a potential timing side-channel attack in Customizer (CVe-2015-5730), an
issue in Heartbeat where an attacker could lock a post from being edited
(CVE-2015-5731), and an SQL injection issue (CVE-2015-2213), as well
as other bugs. See the upstream announcement and release notes for more
details.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.9.8~1.mga4", rls:"MAGEIA4"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0221");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2014-0221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0221");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0221.html");
  script_xref(name:"URL", value:"http://www.egroupware.org/forum#nabble-td3997580");
  script_xref(name:"URL", value:"http://www.egroupware.org/changelog");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13334");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'egroupware, egroupware' package(s) announced via the MGASA-2014-0221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated egroupware packages fix security vulnerabilities:

eGroupWare before 1.8.007 allows logged in users with administrative
privileges to remotely execute arbitrary commands on the server. It is
also vulnerable to a cross site request forgery vulnerability that allows
creating new administrative users.");

  script_tag(name:"affected", value:"'egroupware, egroupware' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"egroupware", rpm:"egroupware~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-bookmarks", rpm:"egroupware-bookmarks~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-calendar", rpm:"egroupware-calendar~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-developer_tools", rpm:"egroupware-developer_tools~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-egw-pear", rpm:"egroupware-egw-pear~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-emailadmin", rpm:"egroupware-emailadmin~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-felamimail", rpm:"egroupware-felamimail~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-filemanager", rpm:"egroupware-filemanager~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-gallery", rpm:"egroupware-gallery~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-importexport", rpm:"egroupware-importexport~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-infolog", rpm:"egroupware-infolog~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-manual", rpm:"egroupware-manual~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-news_admin", rpm:"egroupware-news_admin~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-notifications", rpm:"egroupware-notifications~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-phpbrain", rpm:"egroupware-phpbrain~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-phpsysinfo", rpm:"egroupware-phpsysinfo~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-polls", rpm:"egroupware-polls~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-projectmanager", rpm:"egroupware-projectmanager~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-registration", rpm:"egroupware-registration~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-sambaadmin", rpm:"egroupware-sambaadmin~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-sitemgr", rpm:"egroupware-sitemgr~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-syncml", rpm:"egroupware-syncml~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-timesheet", rpm:"egroupware-timesheet~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-tracker", rpm:"egroupware-tracker~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-wiki", rpm:"egroupware-wiki~1.8.007.20140506~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"egroupware", rpm:"egroupware~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-bookmarks", rpm:"egroupware-bookmarks~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-calendar", rpm:"egroupware-calendar~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-developer_tools", rpm:"egroupware-developer_tools~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-egw-pear", rpm:"egroupware-egw-pear~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-emailadmin", rpm:"egroupware-emailadmin~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-felamimail", rpm:"egroupware-felamimail~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-filemanager", rpm:"egroupware-filemanager~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-gallery", rpm:"egroupware-gallery~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-importexport", rpm:"egroupware-importexport~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-infolog", rpm:"egroupware-infolog~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-manual", rpm:"egroupware-manual~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-news_admin", rpm:"egroupware-news_admin~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-notifications", rpm:"egroupware-notifications~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-phpbrain", rpm:"egroupware-phpbrain~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-phpsysinfo", rpm:"egroupware-phpsysinfo~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-polls", rpm:"egroupware-polls~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-projectmanager", rpm:"egroupware-projectmanager~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-registration", rpm:"egroupware-registration~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-sambaadmin", rpm:"egroupware-sambaadmin~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-sitemgr", rpm:"egroupware-sitemgr~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-syncml", rpm:"egroupware-syncml~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-timesheet", rpm:"egroupware-timesheet~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-tracker", rpm:"egroupware-tracker~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"egroupware-wiki", rpm:"egroupware-wiki~1.8.007.20140506~1.mga4", rls:"MAGEIA4"))) {
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

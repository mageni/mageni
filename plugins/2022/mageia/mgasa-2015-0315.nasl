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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0315");
  script_cve_id("CVE-2014-8878");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-06 19:13:00 +0000 (Fri, 06 Oct 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0315");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0315.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16401");
  script_xref(name:"URL", value:"https://bugs.kde.org/show_bug.cgi?id=340312");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/07/16/10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdepim4' package(s) announced via the MGASA-2015-0315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a security vulnerability in kdepim : kmail doesn't
encrypt attachments when 'automatic encryption' is selected
(CVE-2014-8878).");

  script_tag(name:"affected", value:"'kdepim4' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"akonadiconsole", rpm:"akonadiconsole~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"akregator", rpm:"akregator~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"akregator-handbook", rpm:"akregator-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blogilo", rpm:"blogilo~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blogilo-handbook", rpm:"blogilo-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kaddressbook", rpm:"kaddressbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kaddressbook-handbook", rpm:"kaddressbook-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalarm", rpm:"kalarm~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kalarm-handbook", rpm:"kalarm-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4", rpm:"kdepim4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-core", rpm:"kdepim4-core~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-devel", rpm:"kdepim4-devel~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdepim4-kresources", rpm:"kdepim4-kresources~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kincidenceeditor", rpm:"kincidenceeditor~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kjots", rpm:"kjots~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kjots-handbook", rpm:"kjots-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kleopatra", rpm:"kleopatra~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kleopatra-handbook", rpm:"kleopatra-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmail", rpm:"kmail~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmail-handbook", rpm:"kmail-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmailcvt", rpm:"kmailcvt~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knode", rpm:"knode~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knode-handbook", rpm:"knode-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knotes", rpm:"knotes~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"knotes-handbook", rpm:"knotes-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kontact", rpm:"kontact~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kontact-handbook", rpm:"kontact-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"korganizer", rpm:"korganizer~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"korganizer-handbook", rpm:"korganizer-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ksendemail", rpm:"ksendemail~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktimetracker", rpm:"ktimetracker~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktimetracker-handbook", rpm:"ktimetracker-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktnef", rpm:"ktnef~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ktnef-handbook", rpm:"ktnef-handbook~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akonadi-next4", rpm:"lib64akonadi-next4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akregatorinterfaces4", rpm:"lib64akregatorinterfaces4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64akregatorprivate4", rpm:"lib64akregatorprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64calendarsupport4", rpm:"lib64calendarsupport4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64composereditorng4", rpm:"lib64composereditorng4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64eventviews4", rpm:"lib64eventviews4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64folderarchive4", rpm:"lib64folderarchive4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64grammar4", rpm:"lib64grammar4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64grantleetheme4", rpm:"lib64grantleetheme4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64grantleethemeeditor4", rpm:"lib64grantleethemeeditor4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64incidenceeditorsng4", rpm:"lib64incidenceeditorsng4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64incidenceeditorsngmobile4", rpm:"lib64incidenceeditorsngmobile4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kaddressbookgrantlee4", rpm:"lib64kaddressbookgrantlee4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kaddressbookprivate4", rpm:"lib64kaddressbookprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcal_resourceblog4", rpm:"lib64kcal_resourceblog4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcal_resourceremote4", rpm:"lib64kcal_resourceremote4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdepim4", rpm:"lib64kdepim4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdepimdbusinterfaces4", rpm:"lib64kdepimdbusinterfaces4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdgantt20", rpm:"lib64kdgantt20~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kleo4", rpm:"lib64kleo4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kleopatraclientcore0", rpm:"lib64kleopatraclientcore0~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kleopatraclientgui0", rpm:"lib64kleopatraclientgui0~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmailprivate4", rpm:"lib64kmailprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmanagesieve4", rpm:"lib64kmanagesieve4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knodecommon4", rpm:"lib64knodecommon4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knotesprivate4", rpm:"lib64knotesprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kontactprivate4", rpm:"lib64kontactprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64korganizer_core4", rpm:"lib64korganizer_core4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64korganizer_interfaces4", rpm:"lib64korganizer_interfaces4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64korganizerprivate4", rpm:"lib64korganizerprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpgp4", rpm:"lib64kpgp4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksieve4", rpm:"lib64ksieve4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksieveui4", rpm:"lib64ksieveui4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mailcommon4", rpm:"lib64mailcommon4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mailimporter4", rpm:"lib64mailimporter4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messagecomposer4", rpm:"lib64messagecomposer4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messagecore4", rpm:"lib64messagecore4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messagelist4", rpm:"lib64messagelist4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64messageviewer4", rpm:"lib64messageviewer4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pimactivity4", rpm:"lib64pimactivity4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pimcommon4", rpm:"lib64pimcommon4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sendlater4", rpm:"lib64sendlater4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64templateparser4", rpm:"lib64templateparser4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakonadi-next4", rpm:"libakonadi-next4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakregatorinterfaces4", rpm:"libakregatorinterfaces4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libakregatorprivate4", rpm:"libakregatorprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcalendarsupport4", rpm:"libcalendarsupport4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcomposereditorng4", rpm:"libcomposereditorng4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeventviews4", rpm:"libeventviews4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfolderarchive4", rpm:"libfolderarchive4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrammar4", rpm:"libgrammar4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrantleetheme4", rpm:"libgrantleetheme4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrantleethemeeditor4", rpm:"libgrantleethemeeditor4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libincidenceeditorsng4", rpm:"libincidenceeditorsng4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libincidenceeditorsngmobile4", rpm:"libincidenceeditorsngmobile4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkaddressbookgrantlee4", rpm:"libkaddressbookgrantlee4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkaddressbookprivate4", rpm:"libkaddressbookprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcal_resourceblog4", rpm:"libkcal_resourceblog4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcal_resourceremote4", rpm:"libkcal_resourceremote4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdepim4", rpm:"libkdepim4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdepimdbusinterfaces4", rpm:"libkdepimdbusinterfaces4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdgantt20", rpm:"libkdgantt20~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkleo4", rpm:"libkleo4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkleopatraclientcore0", rpm:"libkleopatraclientcore0~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkleopatraclientgui0", rpm:"libkleopatraclientgui0~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmailprivate4", rpm:"libkmailprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmanagesieve4", rpm:"libkmanagesieve4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknodecommon4", rpm:"libknodecommon4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknotesprivate4", rpm:"libknotesprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkontactprivate4", rpm:"libkontactprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkorganizer_core4", rpm:"libkorganizer_core4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkorganizer_interfaces4", rpm:"libkorganizer_interfaces4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkorganizerprivate4", rpm:"libkorganizerprivate4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpgp4", rpm:"libkpgp4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksieve4", rpm:"libksieve4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksieveui4", rpm:"libksieveui4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmailcommon4", rpm:"libmailcommon4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmailimporter4", rpm:"libmailimporter4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessagecomposer4", rpm:"libmessagecomposer4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessagecore4", rpm:"libmessagecore4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessagelist4", rpm:"libmessagelist4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmessageviewer4", rpm:"libmessageviewer4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpimactivity4", rpm:"libpimactivity4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpimcommon4", rpm:"libpimcommon4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsendlater4", rpm:"libsendlater4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtemplateparser4", rpm:"libtemplateparser4~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"messageviewer", rpm:"messageviewer~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pimactivity", rpm:"pimactivity~4.12.5~1.1.mga4", rls:"MAGEIA4"))) {
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

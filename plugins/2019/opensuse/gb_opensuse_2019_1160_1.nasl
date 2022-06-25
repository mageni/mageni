# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852405");
  script_version("2019-04-06T02:01:12+0000");
  script_cve_id("CVE-2018-11410", "CVE-2018-11440", "CVE-2018-11577", "CVE-2018-11683",
                "CVE-2018-11684", "CVE-2018-11685", "CVE-2018-12085", "CVE-2018-17294");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-06 02:01:12 +0000 (Sat, 06 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-06 02:01:12 +0000 (Sat, 06 Apr 2019)");
  script_name("openSUSE Update for liblouis openSUSE-SU-2019:1160-1 (liblouis)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00038.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblouis'
  package(s) announced via the openSUSE-SU-2019:1160_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for liblouis fixes the following issues:

  Security issues fixed:

  - CVE-2018-17294: Fixed an out of bounds read in matchCurrentInput
  function which could allow a remote attacker to cause Denail of Service
  (bsc#1109319).

  - CVE-2018-11410: Fixed an invalid free in the compileRule function in
  compileTranslationTable.c (bsc#1094685)

  - CVE-2018-11440: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (bsc#1095189)

  - CVE-2018-11577: Fixed a segmentation fault in lou_logPrint in logging.c
  (bsc#1095945)

  - CVE-2018-11683: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (different vulnerability than
  CVE-2018-11440) (bsc#1095827)

  - CVE-2018-11684: Fixed stack-based buffer overflow in the function
  includeFile() in compileTranslationTable.c (bsc#1095826)

  - CVE-2018-11685: Fixed a stack-based buffer overflow in the function
  compileHyphenation() in compileTranslationTable.c (bsc#1095825)

  - CVE-2018-12085: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (different vulnerability than
  CVE-2018-11440) (bsc#1097103)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1160=1");

  script_tag(name:"affected", value:"'liblouis' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"liblouis-data", rpm:"liblouis-data~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-debuginfo", rpm:"liblouis-debuginfo~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-debugsource", rpm:"liblouis-debugsource~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-devel", rpm:"liblouis-devel~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-doc", rpm:"liblouis-doc~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-tools", rpm:"liblouis-tools~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-tools-debuginfo", rpm:"liblouis-tools-debuginfo~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis14", rpm:"liblouis14~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis14-debuginfo", rpm:"liblouis14-debuginfo~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-louis", rpm:"python3-louis~3.3.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

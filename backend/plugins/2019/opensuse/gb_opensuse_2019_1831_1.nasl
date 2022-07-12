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
  script_oid("1.3.6.1.4.1.25623.1.0.852644");
  script_version("2019-08-14T07:16:43+0000");
  script_cve_id("CVE-2016-1238", "CVE-2017-15705", "CVE-2018-11780", "CVE-2018-11781");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-14 07:16:43 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-07 02:07:25 +0000 (Wed, 07 Aug 2019)");
  script_name("openSUSE Update for spamassassin openSUSE-SU-2019:1831-1 (spamassassin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spamassassin'
  package(s) announced via the openSUSE-SU-2019:1831_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for spamassassin to version 3.4.2 fixes the following issues:

  Security issues fixed:

  - CVE-2018-11781: Fixed an issue where a local user could inject code in
  the meta rule syntax (bsc#1108748).

  - CVE-2018-11780: Fixed a potential remote code execution vulnerability in
  the PDFInfo plugin (bsc#1108750).

  - CVE-2017-15705: Fixed a denial of service through unclosed tags in
  crafted emails (bsc#1108745).

  - CVE-2016-1238: Fixed an issue where perl would load modules from the
  current directory (bsc#1108749).

  Non-security issues fixed:

  - Use systemd timers instead of cron (bsc#1115411)

  - Fixed incompatibility with Net::DNS >= 1.01 (bsc#1107765)

  - Fixed warning about deprecated regex during sa-update (bsc#1069831)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1831=1");

  script_tag(name:"affected", value:"'spamassassin' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~lp150.6.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin-Plugin-iXhash2", rpm:"perl-Mail-SpamAssassin-Plugin-iXhash2~2.05~lp150.6.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~lp150.6.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debuginfo", rpm:"spamassassin-debuginfo~3.4.2~lp150.6.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-debugsource", rpm:"spamassassin-debugsource~3.4.2~lp150.6.3.1", rls:"openSUSELeap15.0"))) {
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

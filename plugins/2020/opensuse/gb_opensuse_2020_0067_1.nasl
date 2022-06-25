# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853007");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2018-18246", "CVE-2018-18247", "CVE-2018-18248", "CVE-2018-18249", "CVE-2018-18250");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:18:12 +0000 (Mon, 27 Jan 2020)");
  script_name("openSUSE: Security Advisory for icingaweb2 (openSUSE-SU-2020:0067_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.0|openSUSELeap15\.1)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icingaweb2'
  package(s) announced via the openSUSE-SU-2020:0067_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icingaweb2 to version 2.7.3 fixes the following issues:

  icingaweb2 update to 2.7.3:

  * Fixed an issue where servicegroups for roles with filtered objects were
  not available

  icingaweb2 update to 2.7.2:

  * Performance imrovements and bug fixes

  icingaweb2 update to 2.7.1:

  * Highlight links in the notes of an object

  * Fixed an issue where sort rules were no longer working

  * Fixed an issue where statistics were shown with an anarchist way

  * Fixed an issue where wildcards could no show results

  icingaweb2 update to 2.7.0:

  * New languages support

  * Now module developers got additional ways to customize Icinga Web 2

  * UI enhancements

  icingaweb2 update to 2.6.3:

  * Fixed various issues with LDAP

  * Fixed issues with timezone

  * UI enhancements

  * Stability fixes

  icingaweb2 update to 2.6.2:

  You can find issues and features related to this release on our Roadmap.
  This bugfix release addresses the following topics:

  * Database connections to MySQL 8 no longer fail

  * LDAP connections now have a timeout configuration which defaults to 5
  seconds

  * User groups are now correctly loaded for externally authenticated users

  * Filters are respected for all links in the host and service group
  overviews

  * Fixed permission problems where host and service actions provided by
  modules were missing

  * Fixed an SQL error in the contact list view when filtering for host
  groups

  * Fixed time zone (DST) detection

  * Fixed the contact details view if restrictions are active

  * Doc parser and documentation fixes

  Fix security issues:

  - CVE-2018-18246: fixed an CSRF in moduledisable (boo#1119784)

  - CVE-2018-18247: fixed an XSS via /icingaweb2/navigation/add (boo#1119785)

  - CVE-2018-18248: fixed an XSS attack is possible via query strings or a
  dir parameter (boo#1119801)

  - CVE-2018-18249: fixed an injection of PHP ini-file directives involves
  environment variables as channel to send out information (boo#1119799)

  - CVE-2018-18250: fixed parameters that can break navigation dashlets
  (boo#1119800)

  - Remove setuid from new upstream spec file for following dirs:

  /etc/icingaweb2, /etc/icingaweb/modules, /etc/icingaweb2/modules/setup,
  /etc/icingaweb2/modules/translation, /var/log/icingaweb2

  icingaweb2 updated to 2.6.1:

  - The command audit now logs a command's payload a ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'icingaweb2' package(s) on openSUSE Leap 15.1, openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"icingacli", rpm:"icingacli~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2", rpm:"icingaweb2~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-common", rpm:"icingaweb2-common~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-HTMLPurifier", rpm:"icingaweb2-vendor-HTMLPurifier~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-JShrink", rpm:"icingaweb2-vendor-JShrink~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-Parsedown", rpm:"icingaweb2-vendor-Parsedown~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-dompdf", rpm:"icingaweb2-vendor-dompdf~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-lessphp", rpm:"icingaweb2-vendor-lessphp~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-zf1", rpm:"icingaweb2-vendor-zf1~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-Icinga", rpm:"php-Icinga~2.7.3~lp150.4.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"icingacli", rpm:"icingacli~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2", rpm:"icingaweb2~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-common", rpm:"icingaweb2-common~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-HTMLPurifier", rpm:"icingaweb2-vendor-HTMLPurifier~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-JShrink", rpm:"icingaweb2-vendor-JShrink~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-Parsedown", rpm:"icingaweb2-vendor-Parsedown~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-dompdf", rpm:"icingaweb2-vendor-dompdf~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-lessphp", rpm:"icingaweb2-vendor-lessphp~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icingaweb2-vendor-zf1", rpm:"icingaweb2-vendor-zf1~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-Icinga", rpm:"php-Icinga~2.7.3~lp151.6.5.1", rls:"openSUSELeap15.1"))) {
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

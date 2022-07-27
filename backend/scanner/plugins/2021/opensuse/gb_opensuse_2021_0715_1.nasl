# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853808");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2016-6209", "CVE-2020-13977");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-13 03:03:50 +0000 (Thu, 13 May 2021)");
  script_name("openSUSE: Security Advisory for nagios (openSUSE-SU-2021:0715-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0715-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RCXDSKLLDI4CG7PLAOOYGYVNNNQLL5WP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nagios'
  package(s) announced via the openSUSE-SU-2021:0715-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nagios fixes the following issues:

  - new nagios-exec-start-post script to fix boo#1003362

  - fix nagios_upgrade.sh writing to log file in user controlled directory
       (boo#1182398). The nagios_upgrade.sh script writes the logfile directly
       below /var/log/

     nagios was updated to 4.4.6:

  * Fixed Map display in Internet Explorer 11 (#714)

  * Fixed duplicate properties appearing in statusjson.cgi (#718)

  * Fixed NERD not building when enabled in ./configure (#723)

  * Fixed build process when using GCC 10 (#721)

  * Fixed postauth vulnerabilities in histogram.js, map.js, trends.js
       (CVE-2020-13977, boo#1172794)

  * When using systemd, configuration will be verified before reloading
       (#715)

  * Fixed HARD OK states triggering on the maximum check attempt (#757)

  * Fix for CVE-2016-6209 (boo#989759) - The 'corewindow' parameter (as in
       bringing this to our attention go to Dawid Golunski (boo#1014637)");

  script_tag(name:"affected", value:"'nagios' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"nagios", rpm:"nagios~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-contrib", rpm:"nagios-contrib~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-debuginfo", rpm:"nagios-debuginfo~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-debugsource", rpm:"nagios-debugsource~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-devel", rpm:"nagios-devel~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-www", rpm:"nagios-www~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-www-dch", rpm:"nagios-www-dch~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-www-debuginfo", rpm:"nagios-www-debuginfo~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-theme-exfoliation", rpm:"nagios-theme-exfoliation~4.4.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
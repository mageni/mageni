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
  script_oid("1.3.6.1.4.1.25623.1.0.854172");
  script_version("2021-09-22T08:01:20+0000");
  script_cve_id("CVE-2021-32749");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-27 16:39:00 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-09-17 01:04:00 +0000 (Fri, 17 Sep 2021)");
  script_name("openSUSE: Security Advisory for fail2ban (openSUSE-SU-2021:1274-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1274-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RYBYCPVAMLJBPZO42ZMSVOQTCNN3YNQS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fail2ban'
  package(s) announced via the openSUSE-SU-2021:1274-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fail2ban fixes the following issues:

  - CVE-2021-32749: prevent a command injection via mail command
       (boo#1188610)

  - Integrate change to resolve boo#1146856 and boo#1180738

     Update to 0.11.2

  - increased stability, filter and action updates

     New Features and Enhancements

  * fail2ban-regex:

  - speedup formatted output (bypass unneeded stats creation)

  - extended with prefregex statistic

  - more informative output for `datepattern` (e. g. set from filter) -
         pattern : description

  * parsing of action in jail-configs considers space between action-names
       as separator also (previously only new-line was allowed), for example
       `action = a b` would specify 2 actions `a` and `b`

  * new filter and jail for GitLab recognizing failed application logins
       (gh#fail2ban/fail2ban#2689)

  * new filter and jail for Grafana recognizing failed application logins
       (gh#fail2ban/fail2ban#2855)

  * new filter and jail for SoftEtherVPN recognizing failed application
       logins (gh#fail2ban/fail2ban#2723)

  * `filter.d/guacamole.conf` extended with `logging` parameter to follow
       webapp-logging if it&#x27 s configured (gh#fail2ban/fail2ban#2631)

  * `filter.d/bitwarden.conf` enhanced to support syslog
       (gh#fail2ban/fail2ban#2778)

  * introduced new prefix `{UNB}` for `datepattern` to disable word
       boundaries in regex

  * datetemplate: improved anchor detection for capturing groups `(^...)`

  * datepattern: improved handling with wrong recognized timestamps
       (timezones, no datepattern, etc) as well as some warnings signaling user
       about invalid pattern or zone (gh#fail2ban/fail2ban#2814):

  - filter gets mode in-operation, which gets activated if filter starts
         processing of new messages  in this mode a timestamp read from
         log-line that appeared recently (not an old line), deviating too much
         from now (up too 24h), will be considered as now (assuming a timezone
         issue), so could avoid unexpected bypass of failure (previously
         exceeding `findtime`)

  - better interaction with non-matching optional datepattern or invalid
         timestamps

  - implements special datepattern `{NONE}` - allow to find failures
         totally without date-time in log messages, whereas filter will use now
         as timestamp (gh#fail2ban/fail2ban#2802)

  * performance optimization of `datepattern` (better search algorithm in
       datedetector, especially for single template)

  * fail2ban-client: ex ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'fail2ban' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"fail2ban", rpm:"fail2ban~0.11.2~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitoring-plugins-fail2ban", rpm:"monitoring-plugins-fail2ban~0.11.2~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
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
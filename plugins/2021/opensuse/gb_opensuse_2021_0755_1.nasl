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
  script_oid("1.3.6.1.4.1.25623.1.0.853820");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2020-35701");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-22 03:01:14 +0000 (Sat, 22 May 2021)");
  script_name("openSUSE: Security Advisory for cacti, (openSUSE-SU-2021:0755-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0755-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B7FVNJPZYLTTVIPUOPZKTHXH76RR2RLD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, '
  package(s) announced via the openSUSE-SU-2021:0755-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cacti, cacti-spine fixes the following issues:

     cacti-spine was updated to 1.2.17:

  * Avoid triggering DDos detection in firewalls on large systems

  * Use mysql reconnect option properly

  * Fix possible creashes in various operations

  * Fix remote data collectors pushing too much data to main when performing
       diagnostics

  * Make spine more responsive when remote connection is down

  * Fix various MySQL issues

  * Make spine immune to DST changes

     cacti-spine 1.2.16:

  * Some developer debug log messages falsely labeled as WARNINGS

  * Remove the need of the dos2unix program

  * Fix Spine experiencing MySQL socket error 2002 under load

  * Under heavy load MySQL/MariaDB return 2006 and 2013 errors on query

  * Add backtrace output to stderr for signals

  * Add Data Source turnaround time to debug output

     cacti-spine 1.2.15:

  * Special characters may not always be ignored properly


     cacti was updated to 1.2.17:

  * Fix incorrect handling of fields led to potential XSS issues

  * CVE-2020-35701: Fix SQL Injection vulnerability (boo#1180804)

  * Fix various XSS issues with HTML Forms handling

  * Fix handling of Daylight Saving Time changes

  * Multiple fixes and extensions to plugins

  * Fix multiple display, export, and input validation issues

  * SNMPv3 Password field was not correctly limited

  * Improved regular expression handling for searcu

  * Improved support for RRDproxy

  * Improved behavior on large systems

  * MariaDB/MysQL: Support persistent connections and improve multiple
       operations and options

  * Add Theme &#x27 Midwinter&#x27

  * Modify automation to test for data before creating graphs

  * Add hooks for plugins to show customize graph source and customize
       template url

  * Allow CSRF security key to be refreshed at command line

  * Allow remote pollers statistics to be cleared

  * Allow user to be automatically logged out after admin defined period

  * When replicating, ensure Cacti can detect and verify replica servers");

  script_tag(name:"affected", value:"'cacti, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.17~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.2.17~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.2.17~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.17~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
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
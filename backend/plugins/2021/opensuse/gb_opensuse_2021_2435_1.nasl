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
  script_oid("1.3.6.1.4.1.25623.1.0.854012");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2020-35459");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-22 03:01:58 +0000 (Thu, 22 Jul 2021)");
  script_name("openSUSE: Security Advisory for crmsh (openSUSE-SU-2021:2435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2435-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JZ4AG2NNHICHYHJBLJR3CWGTGZLQBUDP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crmsh'
  package(s) announced via the openSUSE-SU-2021:2435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for crmsh fixes the following issues:

     Update to version 4.3.1+20210624.67223df2:

     - Fix: ocfs2: Skip verifying UUID for ocfs2 device on top of raid or lvm
       on the join node (bsc#1187553)
     - Fix: history: use Path.mkdir instead of mkdir command(bsc#1179999,
       CVE-2020-35459)
     - Dev: crash_test: Add big warnings to have users&#x27  attention to potential
       failover(jsc#SLE-17979)
     - Dev: crash_test: rename preflight_check as crash_test(jsc#SLE-17979)
     - Fix: bootstrap: update sbd watchdog timeout when using diskless SBD with
       qdevice(bsc#1184465)
     - Dev: utils: allow configure link-local ipv6 address(bsc#1163460)
     - Fix: parse: shouldn&#x27 t allow property setting with an empty
       value(bsc#1185423)
     - Fix: help: show help message from argparse(bsc#1175982)");

  script_tag(name:"affected", value:"'crmsh' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"crmsh", rpm:"crmsh~4.3.1+20210702.4e0ee8fb~5.59.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crmsh-scripts", rpm:"crmsh-scripts~4.3.1+20210702.4e0ee8fb~5.59.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crmsh-test", rpm:"crmsh-test~4.3.1+20210702.4e0ee8fb~5.59.1", rls:"openSUSELeap15.3"))) {
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
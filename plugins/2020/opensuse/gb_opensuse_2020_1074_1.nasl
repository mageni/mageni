# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853316");
  script_version("2020-08-07T07:29:19+0000");
  script_cve_id("CVE-2018-15750", "CVE-2018-15751", "CVE-2020-11651", "CVE-2020-11652");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-07 10:04:11 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 03:01:20 +0000 (Mon, 27 Jul 2020)");
  script_name("openSUSE: Security Advisory for salt (openSUSE-SU-2020:1074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1074-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00070.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2020:1074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt contains the following fixes:

  - Fix for TypeError in Tornado importer (bsc#1174165)

  - Require python3-distro only for TW (bsc#1173072)

  - Add docker.logout to docker execution module. (bsc#1165572)

  - Add option to enable/disable force refresh for zypper.

  - Add publish_batch to ClearFuncs exposed methods.

  - Adds test for zypper abbreviation fix.

  - Avoid segfault from 'salt-api' under certain conditions of heavy load
  managing SSH minions. (bsc#1169604)

  - Avoid traceback on debug logging for swarm module. (bsc#1172075)

  - Batch mode now also correctly provides return value. (bsc#1168340)

  - Better import cache handline.

  - Do not make file.recurse state to fail when msgpack 0.5.4. (bsc#1167437)

  - Do not require vendored backports-abc. (bsc#1170288)

  - Fix errors from unit tests due NO_MOCK and NO_MOCK_REASON deprecation.

  - Fix for low rpm_lowpkg unit test.

  - Fix for temp folder definition in loader unit test.

  - Fix for unless requisite when pip is not installed.

  - Fix integration test failure for test_mod_del_repo_multiline_values.

  - Fix regression in service states with reload argument.

  - Fix tornado imports and missing _utils after rebasing patches.

  - Fix status attribute issue in aptpkg test.

  - Improved storage pool or network handling.

  - loop: fix variable names for until_no_eval.

  - Make 'salt.ext.tornado.gen' to use 'salt.ext.backports_abc' on Python 2.

  - Make setup.py script not to require setuptools greater than 9.1.

  - More robust remote port detection.

  - Prevent spurious 'salt-api' stuck processes when managing SSH minions.
  because of logging deadlock. (bsc#1159284)

  - Python3.8 compatibility changes.

  - Removes unresolved merge conflict in yumpkg module.

  - Returns a the list of IPs filtered by the optional network list.

  - Revert broken changes to slspath made on Salt 3000
  (saltstack/salt#56341). (bsc#1170104)

  - Sanitize grains loaded from roster_grains.json cache during 'state.pkg'.

  - Various virt backports from 3000.2.

  - zypperpkg: filter patterns that start with dot. (bsc#1171906)

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1074=1");

  script_tag(name:"affected", value:"'salt' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-salt", rpm:"python2-salt~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3000~lp151.5.21.1", rls:"openSUSELeap15.1"))) {
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

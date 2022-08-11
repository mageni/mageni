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
  script_oid("1.3.6.1.4.1.25623.1.0.853074");
  script_version("2020-03-20T06:19:59+0000");
  script_cve_id("CVE-2019-17361", "CVE-2019-18897");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-20 13:26:01 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-19 04:00:40 +0000 (Thu, 19 Mar 2020)");
  script_name("openSUSE: Security Advisory for salt (openSUSE-SU-2020:0357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00026.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2020:0357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

  - Avoid possible user escalation upgrading salt-master (bsc#1157465)
  (CVE-2019-18897)

  - Fix unit tests failures in test_batch_async tests

  - Batch Async: Handle exceptions, properly unregister and close instances
  after running async batching to avoid CPU starvation of the MWorkers
  (bsc#1162327)

  - RHEL/CentOS 8 uses platform-python instead of python3

  - New configuration option for selection of grains in the minion start
  event.

  - Fix 'os_family' grain for Astra Linux Common Edition

  - Fix for salt-api NET API where unauthenticated attacker could run
  arbitrary code (CVE-2019-17361) (bsc#1162504)

  - Adds disabled parameter to mod_repo in aptpkg module Move token with
  atomic operation Bad API token files get deleted (bsc#1160931)

  - Support for Btrfs and XFS in parted and mkfs added

  - Adds list_downloaded for apt Module to enable pre-downloading support
  Adds virt.(pool<pipe>network)_get_xml functions

  - Various libvirt updates:

  * Add virt.pool_capabilities function

  * virt.pool_running improvements

  * Add virt.pool_deleted state

  * virt.network_define allow adding IP configuration

  - virt: adding kernel boot parameters to libvirt xml

  - Fix to scheduler when data['run'] does not exist (bsc#1159118)

  - Fix virt states to not fail on VMs already stopped

  - Fix applying of attributes for returner rawfile_json (bsc#1158940)

  - xfs: do not fail if type is not present (bsc#1153611)

  - Fix errors when running virt.get_hypervisor function

  - Align virt.full_info fixes with upstream Salt

  - Fix for log checking in x509 test

  - Read repo info without using interpolation (bsc#1135656)

  - Limiting M2Crypto to >= SLE15

  - Replacing pycrypto with M2Crypto (bsc#1165425)

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-357=1");

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

  if(!isnull(res = isrpmvuln(pkg:"python2-salt", rpm:"python2-salt~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~2019.2.0~lp151.5.12.1", rls:"openSUSELeap15.1"))) {
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
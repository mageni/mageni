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
  script_oid("1.3.6.1.4.1.25623.1.0.853953");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2021-21284", "CVE-2021-21285", "CVE-2021-21334", "CVE-2021-30465");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:05:16 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for containerd, (openSUSE-SU-2021:1954-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1954-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OX775QFGRPXXX7W5FDFKP3V5KCNZYD7F");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, '
  package(s) announced via the openSUSE-SU-2021:1954-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, runc fixes the following issues:

     Docker was updated to 20.10.6-ce (bsc#1184768, bsc#1182947, bsc#1181594)

  * Switch version to use -ce suffix rather than _ce to avoid confusing
       other tools (bsc#1182476).

  * CVE-2021-21284: Fixed a potential privilege escalation when the root
       user in the remapped namespace has access to the host filesystem
       (bsc#1181732)

  * CVE-2021-21285: Fixed an issue where pulling a malformed Docker image
       manifest crashes the dockerd daemon (bsc#1181730).

  * btrfs quotas being removed by Docker regularly (bsc#1183855, bsc#1175081)

     runc was updated to v1.0.0~rc93 (bsc#1182451, bsc#1175821 bsc#1184962).

  * Use the upstream runc package (bsc#1181641, bsc#1181677, bsc#1175821).

  * Fixed /dev/null is not available (bsc#1168481).

  * CVE-2021-30465: Fixed a symlink-exchange attack vulnerability
       (bsc#1185405).

     containerd was updated to v1.4.4

  * CVE-2021-21334: Fixed a potential information leak through environment
       variables (bsc#1183397).

  * Handle a requirement from docker (bsc#1181594).");

  script_tag(name:"affected", value:"'containerd, ' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerd-1.4.4", rpm:"containerd-1.4.4~5.32.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr-1.4.4", rpm:"containerd-ctr-1.4.4~5.32.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-20.10.6_ce", rpm:"docker-20.10.6_ce~6.49.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo-20.10.6_ce", rpm:"docker-debuginfo-20.10.6_ce~6.49.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-1.0.0-rc93", rpm:"runc-1.0.0-rc93~1.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo-1.0.0-rc93", rpm:"runc-debuginfo-1.0.0-rc93~1.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion-20.10.6_ce", rpm:"docker-bash-completion-20.10.6_ce~6.49.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion-20.10.6_ce", rpm:"docker-fish-completion-20.10.6_ce~6.49.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion-20.10.6_ce", rpm:"docker-zsh-completion-20.10.6_ce~6.49.3", rls:"openSUSELeap15.3"))) {
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

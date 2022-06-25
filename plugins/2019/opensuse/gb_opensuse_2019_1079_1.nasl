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
  script_oid("1.3.6.1.4.1.25623.1.0.852379");
  script_version("2019-04-26T08:24:31+0000");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-26 08:24:31 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-03 06:42:08 +0000 (Wed, 03 Apr 2019)");
  script_name("openSUSE Update for containerd, openSUSE-SU-2019:1079-1 (containerd, docker, docker-runc, golang-github-docker-libnetwork, runc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00044.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, docker-runc, golang-github-docker-libnetwork, runc'
  package(s) announced via the openSUSE-SU-2019:1079_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc,
  golang-github-docker-libnetwork, runc fixes the following issues:

  Security issues fixed:

  - CVE-2018-16875: Fixed a CPU Denial of Service (bsc#1118899).

  - CVE-2018-16874: Fixed a vulnerabity in go get command which could allow
  directory traversal in GOPATH mode (bsc#1118898).

  - CVE-2018-16873: Fixed a vulnerability in go get command which could
  allow remote code execution when executed with -u in GOPATH mode
  (bsc#1118897).

  - CVE-2019-5736: Effectively copying /proc/self/exe during re-exec to
  avoid write attacks to the host runc binary, which could lead to a
  container breakout (bsc#1121967).

  Other changes and bug fixes:

  - Update shell completion to use Group: System/Shells.

  - Add daemon.json file with rotation logs configuration (bsc#1114832)

  - Update to Docker 18.09.1-ce (bsc#1124308) and to to runc 96ec2177ae84.
  See upstream changelog in the packaged
  /usr/share/doc/packages/docker/CHANGELOG.md.

  - Disable leap based builds for kubic flavor (bsc#1121412).

  - Allow users to explicitly specify the NIS domain name of a container
  (bsc#1001161).

  - Update docker.service to match upstream and avoid rlimit problems
  (bsc#1112980).

  - Update go requirements to >= go1.10

  - Use -buildmode=pie for tests and binary build (bsc#1048046 and
  bsc#1051429).

  - Remove the usage of 'cp -r' to reduce noise in the build logs.

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1079=1");

  script_tag(name:"affected", value:"'containerd, docker, docker-runc, golang-github-docker-libnetwork, runc' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.2~22.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.2.2~22.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-kubic", rpm:"containerd-kubic~1.2.2~22.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-kubic-ctr", rpm:"containerd-kubic-ctr~1.2.2~22.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-kubic", rpm:"docker-libnetwork-kubic~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-kubic-debuginfo", rpm:"docker-libnetwork-kubic-debuginfo~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debugsource", rpm:"docker-runc-debugsource~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-kubic", rpm:"docker-runc-kubic~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-kubic-debuginfo", rpm:"docker-runc-kubic-debuginfo~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-kubic-debugsource", rpm:"docker-runc-kubic-debugsource~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork", rpm:"golang-github-docker-libnetwork~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>golang-github-docker-libnetwork-debugsource", rpm:"<br>golang-github-docker-libnetwork-debugsource~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork-kubic", rpm:"golang-github-docker-libnetwork-kubic~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>golang-github-docker-libnetwork-kubic-debugsource", rpm:"<br>golang-github-docker-libnetwork-kubic-debugsource~0.7.0.1+gitr2711_2cfbf9b1f981~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-kubic-test", rpm:"containerd-kubic-test~1.2.2~22.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-test", rpm:"containerd-test~1.2.2~22.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-bash-completion", rpm:"docker-kubic-bash-completion~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-zsh-completion", rpm:"docker-kubic-zsh-completion~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-kubic-test", rpm:"docker-runc-kubic-test~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-test", rpm:"docker-runc-test~1.0.0rc6+gitr3748_96ec2177ae84~11.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic", rpm:"docker-kubic~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-debuginfo", rpm:"docker-kubic-debuginfo~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-debugsource", rpm:"docker-kubic-debugsource~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-kubeadm-criconfig", rpm:"docker-kubic-kubeadm-criconfig~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-test", rpm:"docker-kubic-test~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-test-debuginfo", rpm:"docker-kubic-test-debuginfo~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test", rpm:"docker-test~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test-debuginfo", rpm:"docker-test-debuginfo~18.09.1_ce~54.1", rls:"openSUSELeap42.3"))) {
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
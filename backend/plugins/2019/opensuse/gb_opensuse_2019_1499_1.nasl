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
  script_oid("1.3.6.1.4.1.25623.1.0.852536");
  script_version("2019-06-04T07:02:10+0000");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736", "CVE-2019-6486");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-04 07:02:10 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-04 02:00:58 +0000 (Tue, 04 Jun 2019)");
  script_name("openSUSE Update for containerd, openSUSE-SU-2019:1499-1 (containerd, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, '
  package(s) announced via the openSUSE-SU-2019:1499_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc, go, go1.11, go1.12,
  golang-github-docker-libnetwork fixes the following issues:

  Security issues fixed:

  - CVE-2019-5736: containerd: Fixing container breakout vulnerability
  (bsc#1121967).

  - CVE-2019-6486: go security release, fixing crypto/elliptic CPU DoS
  vulnerability affecting P-521 and P-384 (bsc#1123013).

  - CVE-2018-16873: go secuirty release, fixing cmd/go remote command
  execution (bsc#1118897).

  - CVE-2018-16874: go security release, fixing cmd/go directory traversal
  (bsc#1118898).

  - CVE-2018-16875: go security release, fixing crypto/x509 CPU denial of
  service (bsc#1118899).

  Other changes and bug fixes:

  - Update to containerd v1.2.5, which is required for v18.09.5-ce
  (bsc#1128376, bsc#1134068).

  - Update to runc 2b18fe1d885e, which is required for Docker v18.09.5-ce
  (bsc#1128376, bsc#1134068).

  - Update to Docker 18.09.5-ce see upstream changelog in the packaged
  (bsc#1128376, bsc#1134068).

  - docker-test: Improvements to test packaging (bsc#1128746).

  - Move daemon.json file to /etc/docker directory (bsc#1114832).

  - Revert golang(API) removal since it turns out this breaks >= requires in
  certain cases (bsc#1114209).

  - Fix go build failures (bsc#1121397).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1499=1");

  script_tag(name:"affected", value:"'containerd, ' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"go", rpm:"go~1.12~lp150.2.11.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go-doc", rpm:"go-doc~1.12~lp150.2.11.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-test", rpm:"containerd-test~1.2.5~lp150.4.14.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-test", rpm:"docker-runc-test~1.0.0rc6+gitr3804_2b18fe1d885e~lp150.5.21.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.5~lp150.4.14.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.2.5~lp150.4.14.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2726_872f0a83c98a~lp150.3.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2726_872f0a83c98a~lp150.3.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc6+gitr3804_2b18fe1d885e~lp150.5.21.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc6+gitr3804_2b18fe1d885e~lp150.5.21.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test", rpm:"docker-test~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test-debuginfo", rpm:"docker-test-debuginfo~18.09.6_ce~lp150.5.17.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go-race", rpm:"go-race~1.12~lp150.2.11.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.11", rpm:"go1.11~1.11.9~lp150.9.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.11-doc", rpm:"go1.11-doc~1.11.9~lp150.9.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.11-race", rpm:"go1.11-race~1.11.9~lp150.9.3", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.12", rpm:"go1.12~1.12.4~lp150.2.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.12-doc", rpm:"go1.12-doc~1.12.4~lp150.2.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.12-race", rpm:"go1.12-race~1.12.4~lp150.2.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork", rpm:"golang-github-docker-libnetwork~0.7.0.1+gitr2726_872f0a83c98a~lp150.3.14.1", rls:"openSUSELeap15.0"))) {
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

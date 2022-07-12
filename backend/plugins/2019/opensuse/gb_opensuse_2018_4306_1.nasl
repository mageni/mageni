###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4306_1.nasl 13561 2019-02-11 07:33:41Z mmartin $
#
# SuSE Update for containerd, openSUSE-SU-2018:4306-1 (containerd,)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852218");
  script_version("$Revision: 13561 $");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2018-7187");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 08:33:41 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-01 04:00:47 +0100 (Tue, 01 Jan 2019)");
  script_name("SuSE Update for containerd, openSUSE-SU-2018:4306-1 (containerd, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00076.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, '
  package(s) announced via the openSUSE-SU-2018:4306_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker and go fixes the following issues:

  containerd and docker:

  - Add backport for building containerd (bsc#1102522, bsc#1113313)

  - Upgrade to containerd v1.1.2, which is required for Docker v18.06.1-ce.
  (bsc#1102522)

  - Enable seccomp support (fate#325877)

  - Update to containerd v1.1.1, which is the required version for the
  Docker v18.06.0-ce upgrade. (bsc#1102522)

  - Put containerd under the podruntime slice (bsc#1086185)

  - 3rd party registries used the default Docker certificate (bsc#1084533)

  - Handle build breakage due to missing 'export GOPATH' (caused by
  resolution of boo#1119634). I believe Docker is one of the only packages
  with this problem.

  go:

  - golang: arbitrary command execution via VCS path (bsc#1081495,
  CVE-2018-7187)

  - Make profile.d/go.sh no longer set GOROOT=, in order to make switching
  between versions no longer break. This ends up removing the need for
  go.sh entirely (because GOPATH is also set automatically) (boo#1119634)

  - Fix a regression that broke go get for import path patterns containing
  '...' (bsc#1119706)

  Additionally, the package go1.10 has been added.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1626=1");

  script_tag(name:"affected", value:"containerd, on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"go", rpm:"go~1.10.4~lp150.2.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go-doc", rpm:"go-doc~1.10.4~lp150.2.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.1.2~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.1.2~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-kubic", rpm:"containerd-kubic~1.1.2~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-kubic-ctr", rpm:"containerd-kubic-ctr~1.1.2~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker", rpm:"docker~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic", rpm:"docker-kubic~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic-debuginfo", rpm:"docker-kubic-debuginfo~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic-debugsource", rpm:"docker-kubic-debugsource~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic-test", rpm:"docker-kubic-test~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic-test-debuginfo", rpm:"docker-kubic-test-debuginfo~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2664_3ac297bc7fd0~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2664_3ac297bc7fd0~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-libnetwork-kubic", rpm:"docker-libnetwork-kubic~0.7.0.1+gitr2664_3ac297bc7fd0~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"<br>docker-libnetwork-kubic-debuginfo", rpm:"<br>docker-libnetwork-kubic-debuginfo~0.7.0.1+gitr2664_3ac297bc7fd0~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-kubic", rpm:"docker-runc-kubic~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-kubic-debuginfo", rpm:"docker-runc-kubic-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-test", rpm:"docker-test~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-test-debuginfo", rpm:"docker-test-debuginfo~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go-race", rpm:"go-race~1.10.4~lp150.2.7.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.10", rpm:"go1.10~1.10.7~lp150.2.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.10-doc", rpm:"go1.10-doc~1.10.7~lp150.2.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"go1.10-race", rpm:"go1.10-race~1.10.7~lp150.2.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-github-docker-libnetwork", rpm:"golang-github-docker-libnetwork~0.7.0.1+gitr2664_3ac297bc7fd0~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"<br>golang-github-docker-libnetwork-kubic", rpm:"<br>golang-github-docker-libnetwork-kubic~0.7.0.1+gitr2664_3ac297bc7fd0~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-kubic-test", rpm:"containerd-kubic-test~1.1.2~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"containerd-test", rpm:"containerd-test~1.1.2~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic-bash-completion", rpm:"docker-kubic-bash-completion~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-kubic-zsh-completion", rpm:"docker-kubic-zsh-completion~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-kubic-test", rpm:"docker-runc-kubic-test~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-runc-test", rpm:"docker-runc-test~1.0.0rc5+gitr3562_69663f0bd4b6~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~18.06.1_ce~lp150.5.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"golang-packaging", rpm:"golang-packaging~15.0.11~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

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
  script_oid("1.3.6.1.4.1.25623.1.0.854260");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-30465", "CVE-2021-32760", "CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092", "CVE-2021-41103");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 02:03:11 +0000 (Mon, 01 Nov 2021)");
  script_name("openSUSE: Security Advisory for containerd, (openSUSE-SU-2021:1404-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1404-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/L7ADRJZ4HKOCVZC5ZKIM4MD6EZEHBNB3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, '
  package(s) announced via the openSUSE-SU-2021:1404-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, runc fixes the following issues:

     Docker was updated to 20.10.9-ce. (bsc#1191355)

     See upstream changelog in the packaged
     /usr/share/doc/packages/docker/CHANGELOG.md.

       CVE-2021-41092 CVE-2021-41089 CVE-2021-41091 CVE-2021-41103

     container was updated to v1.4.11, to fix CVE-2021-41103. bsc#1191355

  - CVE-2021-32760: Fixed that a archive package allows chmod of file
       outside of unpack target directory (bsc#1188282)

  - Install systemd service file as well (bsc#1190826)

  * Fixed a failure to set CPU quota period in some cases on cgroup v1.

  * Fixed the inability to start a container with the 'adding seccomp filter
       rule for syscall ...' error, caused by redundant seccomp rules (i.e.
       those that has action equal to the default one). Such redundant rules
       are now skipped.

  * Made release builds reproducible from now on.

  * Fixed a rare debug log race in runc init, which can result in occasional
       harmful 'failed to decode ...' errors from runc run or exec.

  * Fixed the check in cgroup v1 systemd manager if a container needs to be
       frozen before Set, and add a setting to skip such freeze
       unconditionally. The previous fix for that issue, done in runc 1.0.1,
       was not working.

  * Fixed occasional runc exec/run failure ('interrupted system call') on an
       Azure volume.

  * Fixed 'unable to find groups ... token too long' error with /etc/group
       containing lines longer than 64K characters.

  * cgroup/systemd/v1: fix leaving cgroup frozen after Set if a parent
       cgroup is frozen. This is a regression in 1.0.0, not affecting runc
       itself but some
       of libcontainer users (e.g Kubernetes).

  * cgroupv2: bpf: Ignore inaccessible existing programs in case of
       permission error when handling replacement of existing bpf cgroup
       programs. This fixes a regression in 1.0.0, where some SELinux policies
       would block runc from being able to run entirely.

  * cgroup/systemd/v2: don&#x27 t freeze cgroup on Set.

  * cgroup/systemd/v1: avoid unnecessary freeze on Set.

  - fix issues with ru ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'containerd, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.9_ce~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.9_ce~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~20.10.9_ce~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.4.11~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.4.11~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.9_ce~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.9_ce~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.0.2~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.0.2~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
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

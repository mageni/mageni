# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854800");
  script_version("2022-07-13T10:13:19+0000");
  script_cve_id("CVE-2022-29162", "CVE-2022-31030");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-13 10:13:19 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-01 16:41:00 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-07-09 01:02:05 +0000 (Sat, 09 Jul 2022)");
  script_name("openSUSE: Security Advisory for containerd(SUSE-SU-2022:2341-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2341-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N3L2STYSDA7TUJTOUX5236ITDNVPEKQU");

  script_tag(name:"summary", value:"The remote host is missing an update for the containerd package(s) announced via the SUSE-SU-2022:2341-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker and runc fixes the following issues:
  containerd:

  - CVE-2022-31030: Fixed denial of service via invocation of the ExecSync
       API (bsc#1200145)
  docker:

  * Retry on dbus disconnect logic in libcontainer/cgroups/systemd now works
       as intended  this fix does not affect runc binary itself but is
       important for libcontainer users such as Kubernetes.

  * Inability to compile with recent clang due to an issue with duplicate
       constants in libseccomp-golang.

  * When using systemd cgroup driver, skip adding device paths that don't
       exist, to stop systemd from emitting warnings about those paths.

  * Socket activation was failing when more than 3 sockets were used.

  * Various CI fixes.

  * Allow to bind mount /proc/sys/kernel/ns_last_pid to inside container.

  - Fixed issues with newer syscalls (namely faccessat2) on older kernels on
       s390(x) caused by that platform's syscall multiplexing semantics.
       (bsc#1192051 bsc#1199565)
  Update to runc v1.1.2.

  - CVE-2022-29162: A bug was found in runc where runc exec --cap executed
       processes with non-empty inheritable Linux process capabilities,
       creating an atypical Linux environment. (bsc#1199460)


  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"containerd package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.6.6~150000.73.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.6.6~150000.73.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic", rpm:"docker-kubic~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-debuginfo", rpm:"docker-kubic-debuginfo~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-kubeadm-criconfig", rpm:"docker-kubic-kubeadm-criconfig~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.1.3~150000.30.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.1.3~150000.30.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-bash-completion", rpm:"docker-kubic-bash-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-fish-completion", rpm:"docker-kubic-fish-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-zsh-completion", rpm:"docker-kubic-zsh-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.6.6~150000.73.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.6.6~150000.73.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic", rpm:"docker-kubic~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-debuginfo", rpm:"docker-kubic-debuginfo~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-kubeadm-criconfig", rpm:"docker-kubic-kubeadm-criconfig~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.1.3~150000.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.1.3~150000.30.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-bash-completion", rpm:"docker-kubic-bash-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-fish-completion", rpm:"docker-kubic-fish-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-kubic-zsh-completion", rpm:"docker-kubic-zsh-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~20.10.17_ce~150000.166.1", rls:"openSUSELeap15.3"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3896.1");
  script_cve_id("CVE-2022-1708");
  script_tag(name:"creation_date", value:"2022-11-09 04:35:19 +0000 (Wed, 09 Nov 2022)");
  script_version("2022-11-09T04:35:19+0000");
  script_tag(name:"last_modification", value:"2022-11-09 04:35:19 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-14 15:44:00 +0000 (Tue, 14 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3896-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3896-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223896-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conmon' package(s) announced via the SUSE-SU-2022:3896-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for conmon fixes the following issues:

conmon was updated to 2.1.3:

Stop using g_unix_signal_add() to avoid threads

Rename CLI optionlog-size-global-max to log-global-size-max

Update to version 2.1.2:

add log-global-size-max option to limit the total output conmon
 processes (CVE-2022-1708 bsc#1200285)

journald: print tag and name if both are specified

drop some logs to debug level

Update to version 2.1.0

logging: buffer partial messages to journald

exit: close all fds >= 3

fix: cgroup: Free memory_cgroup_file_path if open fails. Call g_free
 instead of free.

Update to version 2.0.32

Fix: Avoid mainfd_std{in,out} sharing the same file descriptor.

exit_command: Fix: unset subreaper attribute before running exit command

Update to version 2.0.31

logging: new mode -l passthrough

ctr_logs: use container name or ID as SYSLOG_IDENTIFIER for journald

conmon: Fix: free userdata files before exec cleanup

Update to version 2.0.30:

Remove unreachable code path

exit: report if the exit command was killed

exit: fix race zombie reaper

conn_sock: allow watchdog messages through the notify socket proxy

seccomp: add support for seccomp notify

Update to version 2.0.29:

Reset OOM score back to 0 for container runtime

call functions registered with atexit on SIGTERM

conn_sock: fix potential segfault

Update to version 2.0.27:

Add CRI-O integration test GitHub action

exec: don't fail on EBADFD

close_fds: fix close of external fds

Add arm64 static build binary

Update to version 2.0.26:

conn_sock: do not fail on EAGAIN

fix segfault from a double freed pointer

Fix a bug where conmon could never spawn a container, because a
 disagreement between the caller and itself on where the attach socket
 was.

improve --full-attach to ignore the socket-dir directly. that means
 callers don't need to specify a socket dir at all (and can remove it)

add full-attach option to allow callers to not truncate a very long path
 for the attach socket

close only opened FDs

set locale to inherit environment

Update to version 2.0.22:

added man page

attach: always chdir

conn_sock: Explicitly free a heap-allocated string

refactor I/O and add SD_NOTIFY proxy support

Update to version 2.0.21:

protect against kill(-1)

Makefile: enable debuginfo generation

Remove go.sum file and add go.mod

Fail if conmon config could not be written

nix: remove double definition for e2fsprogs

Speedup static build by utilizing CI cache on `/nix` folder

Fix nix build for failing e2fsprogs tests

test: fix CI

Use Podman for building");

  script_tag(name:"affected", value:"'conmon' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.3~150100.3.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.3~150100.3.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.3~150100.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.3~150100.3.9.1", rls:"SLES15.0SP2"))) {
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

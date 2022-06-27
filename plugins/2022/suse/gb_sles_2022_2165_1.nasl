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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2165.1");
  script_cve_id("CVE-2022-29162", "CVE-2022-31030");
  script_tag(name:"creation_date", value:"2022-06-24 04:35:11 +0000 (Fri, 24 Jun 2022)");
  script_version("2022-06-24T04:35:11+0000");
  script_tag(name:"last_modification", value:"2022-06-24 04:35:11 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-01 16:41:00 +0000 (Wed, 01 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2165-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222165-1/");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/#201017");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.1.3");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.1.2");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.1.1");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.1.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd' package(s) announced via the SUSE-SU-2022:2165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd fixes the following issues:

containerd:

CVE-2022-31030: Fixed denial of service via invocation of the ExecSync
 API (bsc#1200145)

docker:

Update to Docker 20.10.17-ce. See upstream changelog online at
 [link moved to references] . bsc#1200145

runc:

Update to runc v1.1.3.

Upstream changelog is available from [link moved to references].

Our seccomp `-ENOSYS` stub now correctly handles multiplexed syscalls on
 s390 and s390x. This solves the issue where syscalls the host kernel did
 not support would return `-EPERM` despite the existence of the `-ENOSYS`
 stub code (this was due to how s390x does syscall multiplexing).

Retry on dbus disconnect logic in libcontainer/cgroups/systemd now works
 as intended, this fix does not affect runc binary itself but is
 important for libcontainer users such as Kubernetes.

Inability to compile with recent clang due to an issue with duplicate
 constants in libseccomp-golang.

When using systemd cgroup driver, skip adding device paths that don't
 exist, to stop systemd from emitting warnings about those paths.

Socket activation was failing when more than 3 sockets were used.

Various CI fixes.

Allow to bind mount /proc/sys/kernel/ns_last_pid to inside container.

Fix issues with newer syscalls (namely faccessat2) on older kernels on
 s390(x) caused by that platform's syscall multiplexing semantics.
 (bsc#1192051 bsc#1199565)

Update to runc v1.1.2.

Upstream changelog is available from [link moved to references].

Security issue fixed:

CVE-2022-29162: A bug was found in runc where runc exec --cap executed
 processes with non-empty inheritable Linux process capabilities,
 creating an atypical Linux environment. (bsc#1199460)

runc spec no longer sets any inheritable capabilities in the created
 example OCI spec (config.json) file.

Update to runc v1.1.1.

Upstream changelog is available from [link moved to references].

runc run/start can now run a container with read-only /dev in OCI spec,
 rather than error out. (#3355)

runc exec now ensures that --cgroup argument is a sub-cgroup. (#3403)
 libcontainer systemd v2 manager no longer errors out if one of the files
 listed in /sys/kernel/cgroup/delegate do not exist in container's
 cgroup. (#3387, #3404)

Loosen OCI spec validation to avoid bogus 'Intel RDT is not supported'
 error. (#3406)

libcontainer/cgroups no longer panics in cgroup v1 managers if stat
 of /sys/fs/cgroup/unified returns an error other than ENOENT. (#3435)

Update to runc v1.1.0.

Upstream changelog is available from [link moved to references].

libcontainer will now refuse to build without the nsenter package being
 correctly compiled (specifically this requires CGO to be enabled). This
 should avoid folks accidentally creating ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'containerd' package(s) on SUSE Linux Enterprise Module for Containers 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.6.6~16.62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.17_ce~98.83.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.17_ce~98.83.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.1.3~16.21.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.1.3~16.21.1", rls:"SLES12.0"))) {
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

# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1812.1");
  script_cve_id("CVE-2023-0778");
  script_tag(name:"creation_date", value:"2023-04-12 04:19:34 +0000 (Wed, 12 Apr 2023)");
  script_version("2023-04-12T11:20:00+0000");
  script_tag(name:"last_modification", value:"2023-04-12 11:20:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-03 16:59:00 +0000 (Mon, 03 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1812-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231812-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the SUSE-SU-2023:1812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:
Update to version 4.4.4:

libpod: always use direct mapping macos pkginstaller: do not fail when podman-mac-helper fails

podman-mac-helper: install: do not error if already installed


podman.spec: Bump required version for libcontainers-common (bsc#1209495)


Update to version 4.4.3:

compat: /auth: parse server address correctly vendor github.com/containers/common@v0.51.1 pkginstaller: bump Qemu to version 7.2.0 podman machine: Adjust Chrony makestep config
[v4.4] fix --health-on-failure=restart in transient unit podman logs passthrough driver support --cgroups=split journald logs: simplify entry parsing podman logs: read journald with passthrough journald: remove initializeJournal()
netavark: only use aardvark ip as nameserver compat API: network create return 409 for duplicate fix 'podman logs --since --follow' flake system service --log-level=trace: support hijack podman-mac-helper: exit 1 on error bump golang.org/x/net to v0.8.0 Fix package restore Quadlet - use the default runtime

Update podman to version 4.4.2:

kube play: only enforce passthrough in Quadlet Emergency fix for man pages: check for broken includes quadlet system tests: add useful defaults, logging volume,container: chroot to source before exporting content install sigproxy before start/attach Update to c/image 5.24.1

events + container inspect test: RHEL fixes


Add crun requirement for quadlet


Set PREFIX at build stage (bsc#1208510)


CVE-2023-0778: fixed symlink exchange attack in podman export volume (bsc#1208364)


Update to version 4.4.1:

kube play: do not teardown unconditionally on error Resolve symlink path for qemu directory if possible events: document journald identifiers Quadlet: exit 0 when there are no files to process Cleanup podman-systemd.unit file Install podman-systemd.unit man page, make quadlet discoverable Add missing return after errors oci: bind mount /sys with --userns=(auto<pipe>pod:)
docs: specify order preference for FROM Cirrus: Fix & remove GraphQL API tests test: adapt test to work on cgroupv1 make hack/markdown-preprocess parallel-safe Fix default handling of pids-limit system tests: fix volume exec/noexec test

Update to version 4.4.0:

Do not mount /dev/tty into rootless containers Fixes port collision issue on use of --publish-all Fix usage of absolute windows paths with --image-path fix #17244: use /etc/timezone where timedatectl is missing on Linux podman-events: document verbose create events Making gvproxy.exe optional for building Windows installer Add gvproxy to Windows packages Match VT device paths to be blocked from mounting exactly Clean up more language for inclusiveness Set runAsNonRoot=true in gen kube quadlet: Add device support for .volume files fix: running check error when podman is default in wsl fix: don't output 'ago' when container is currently up and running journald: podman logs only ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'podman' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.4.4~150300.9.20.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~4.4.4~150300.9.20.1", rls:"SLES15.0SP3"))) {
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

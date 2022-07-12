# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853465");
  script_version("2020-10-01T09:58:23+0000");
  script_cve_id("CVE-2020-1726");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-02 10:00:49 +0000 (Fri, 02 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 03:02:13 +0000 (Tue, 29 Sep 2020)");
  script_name("openSUSE: Security Advisory for conmon, (openSUSE-SU-2020:1559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1559-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00103.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conmon, '
  package(s) announced via the openSUSE-SU-2020:1559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for conmon, fuse-overlayfs, libcontainers-common, podman fixes
  the following issues:

  podman was updated to v2.0.6 (bsc#1175821)

  - install missing systemd units for the new Rest API (bsc#1175957) and a
  few man-pages that where missing before

  - Drop varlink API related bits (in favor of the new API)

  - fix install location for zsh completions

  * Fixed a bug where running systemd in a container on a cgroups v1 system
  would fail.

  * Fixed a bug where /etc/passwd could be re-created every time a
  container is restarted if the container's /etc/passwd did not contain
  an entry for the user the container was started as.

  * Fixed a bug where containers without an /etc/passwd file specifying a
  non-root user would not start.

  * Fixed a bug where the --remote flag would sometimes not make remote
  connections and would instead attempt to run Podman locally.

  Update to v2.0.6:

  * Features

  - Rootless Podman will now add an entry to /etc/passwd for the user who
  ran Podman if run with --userns=keep-id.

  - The podman system connection command has been reworked to support
  multiple connections, and re-enabled for use!

  - Podman now has a new global flag, --connection, to specify a
  connection to a remote Podman API instance.

  * Changes

  - Podman's automatic systemd integration (activated by the

  - -systemd=true flag, set by default) will now activate for containers
  using /usr/local/sbin/init as their command, instead of just
  /usr/sbin/init and /sbin/init (and any path ending in systemd).

  - Seccomp profiles specified by the --security-opt seccomp=... flag to
  podman create and podman run will now be honored even if the container
  was created using --privileged.

  * Bugfixes

  - Fixed a bug where the podman play kube would not honor the hostIP
  field for port forwarding (#5964).

  - Fixed a bug where the podman generate systemd command would panic on
  an invalid restart policy being specified (#7271).

  - Fixed a bug where the podman images command could take a very long
  time (several minutes) to complete when a large number of images were
  present.

  - Fixed a bug where the podman logs command with the --tail flag would
  not work properly when a large amount of output would be printed

  - Fixed a bug where the podman exec command with remote Podman would not
  return a non-zero exit code when the exec session failed to start
  (e.g. invoking a non-existent command) (#6893).

  - Fixed a bug where the podman load command with remote Podma ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'conmon, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20200727~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~2.0.6~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.0.20~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.0.20~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs", rpm:"fuse-overlayfs~1.1.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debuginfo", rpm:"fuse-overlayfs-debuginfo~1.1.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debugsource", rpm:"fuse-overlayfs-debugsource~1.1.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~2.0.6~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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

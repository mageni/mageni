# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853085");
  script_version("2020-03-31T10:29:41+0000");
  script_cve_id("CVE-2019-18466");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-29 03:02:12 +0000 (Sun, 29 Mar 2020)");
  script_name("openSUSE: Security Advisory for cni, (openSUSE-SU-2020:0398-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00040.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cni, '
  package(s) announced via the openSUSE-SU-2020:0398-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cni, cni-plugins, conmon, fuse-overlayfs, podman fixes the
  following issues:

  podman was updated to 1.8.0:

  - CVE-2019-18466: Fixed a bug where podman cp would improperly copy files
  on the host when copying a symlink in the container that included a glob
  operator (#3829 bsc#1155217)

  - The name of the cni-bridge in the default config changed from 'cni0' to
  'podman-cni0' with podman-1.6.0. Add a %trigger to rename the bridge in
  the system to the new default if it exists. The trigger is only executed
  when updating podman-cni-config from something older than 1.6.0. This is
  mainly needed for SLE where we're updating from 1.4.4 to 1.8.0
  (bsc#1160460).

  Update podman to v1.8.0 (bsc#1160460):

  * Features

  - The podman system service command has been added, providing a preview
  of Podman's new Docker-compatible API. This API is still very new, and
  not yet ready for production use, but is available for early testing

  - Rootless Podman now uses Rootlesskit for port forwarding, which should
  greatly improve performance and capabilities

  - The podman untag command has been added to remove tags from images
  without deleting them

  - The podman inspect command on images now displays previous names they
  used

  - The podman generate systemd command now supports a --new
  option to generate service files that create and run new containers
  instead of managing existing containers

  - Support for --log-opt tag= to set logging tags has been added to the
  journald log driver

  - Added support for using Seccomp profiles embedded in images for podman
  run and podman create via the new --seccomp-policy CLI flag

  - The podman play kube command now honors pull policy

  * Bugfixes

  - Fixed a bug where the podman cp command would not copy the contents of
  directories when paths ending in /. were given

  - Fixed a bug where the podman play kube command did not properly locate
  Seccomp profiles specified relative to localhost

  - Fixed a bug where the podman info command for remote Podman did not
  show registry information

  - Fixed a bug where the podman exec command did not support having input
  piped into it

  - Fixed a bug where the podman cp command with rootless Podman
  on CGroups v2 systems did not properly determine if the container
  could be paused while copying

  - Fixed a bug where the podman container prune --force command could
  possible remove running containers if they were started while the
  command was running

  - Fixed a bug where Podman, when run as root, would not properly
  configure slirp4netns networking when requested

  - Fixed a ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'cni, ' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"cni", rpm:"cni~0.7.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cni-plugins", rpm:"cni-plugins~0.8.4~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.0.10~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.0.10~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs", rpm:"fuse-overlayfs~0.7.6~lp151.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debuginfo", rpm:"fuse-overlayfs-debuginfo~0.7.6~lp151.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debugsource", rpm:"fuse-overlayfs-debugsource~0.7.6~lp151.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~1.8.0~lp151.3.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~1.8.0~lp151.3.9.1", rls:"openSUSELeap15.1"))) {
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

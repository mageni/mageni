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
  script_oid("1.3.6.1.4.1.25623.1.0.852813");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2018-15664", "CVE-2019-10152", "CVE-2019-6778");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:33:10 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for podman, openSUSE-SU-2019:2044-1 (podman, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman, '
  package(s) announced via the openSUSE-SU-2019:2044_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a version update for podman to version 1.4.4 (bsc#1143386).

  Additional changes by SUSE on top:

  - Remove fuse-overlayfs because it's (currently) an unsatisfied dependency
  on SLE (bsc#1143386)

  - Update libpod.conf to use correct infra_command

  - Update libpod.conf to use better versioned pause container

  - Update libpod.conf to use official kubic pause container

  - Update libpod.conf to match latest features set: detach_keys, lock_type,
  runtime_supports_json

  - Add podman-remote varlink client

  Version update podman to v1.4.4:

  - Features

  - Podman now has greatly improved support for containers using multiple
  OCI runtimes. Containers now remember if they were created with a
  different runtime using --runtime and will always use that runtime

  - The cached and delegated options for volume mounts are now allowed for
  Docker compatibility (#3340)

  - The podman diff command now supports the --latest flag

  - Bugfixes

  - Fixed a bug where rootless Podman would attempt to use the entire root
  configuration if no rootless configuration was present for the user,
  breaking rootless Podman for new installations

  - Fixed a bug where rootless Podman's pause process would block SIGTERM,
  preventing graceful system shutdown and hanging until the system's
  init send SIGKILL

  - Fixed a bug where running Podman as root with sudo -E would not work
  after running rootless Podman at least once

  - Fixed a bug where options for tmpfs volumes added with the --tmpfs
  flag were being ignored

  - Fixed a bug where images with no layers could not properly be
  displayed and removed by Podman

  - Fixed a bug where locks were not properly freed on failure to create a
  container or pod

  - Fixed a bug where podman cp on a single file would create a directory
  at the target and place the file in it (#3384)

  - Fixed a bug where podman inspect --format '{{.Mounts}}' would print a
  hexadecimal address instead of a container's mounts

  - Fixed a bug where rootless Podman would not add an entry to
  container's /etc/hosts files for their own hostname (#3405)

  - Fixed a bug where podman ps --sync would segfault (#3411)

  - Fixed a bug where podman generate kube would produce an invalid ports
  configuration (#3408)

  - Misc

  - Updated containers/storage to v1.12.13

  - Podman now performs much better on systems with heavy I/O load

  - The --cgroup-manager flag to podman now shows the correct default
  setting in help if the default was overridden by libpod.conf

  - For backwards compatibility, setting --log-driver=json-file in podman
  run is now supported as an alias ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'podman, ' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs", rpm:"fuse-overlayfs~0.4.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debuginfo", rpm:"fuse-overlayfs-debuginfo~0.4.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debugsource", rpm:"fuse-overlayfs-debugsource~0.4.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3", rpm:"fuse3~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3-debuginfo", rpm:"fuse3-debuginfo~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3-debugsource", rpm:"fuse3-debugsource~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3-devel", rpm:"fuse3-devel~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3-doc", rpm:"fuse3-doc~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfuse3-3", rpm:"libfuse3-3~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfuse3-3-debuginfo", rpm:"libfuse3-3-debuginfo~3.6.1~lp151.2.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~1.4.4~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slirp4netns", rpm:"slirp4netns~0.3.0~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slirp4netns-debuginfo", rpm:"slirp4netns-debuginfo~0.3.0~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slirp4netns-debugsource", rpm:"slirp4netns-debugsource~0.3.0~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20190401~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~1.4.4~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.853697");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2019-10214", "CVE-2020-10696");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:00:10 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for buildah, (openSUSE-SU-2021:0310-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0310-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/P4DQSPUPKAZCPS5MQYTAYGS7YM76UIHZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, '
  package(s) announced via the openSUSE-SU-2021:0310-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah, libcontainers-common, podman fixes the following
     issues:

     Changes in libcontainers-common:

  - Update common to 0.33.0

  - Update image to 5.9.0

  - Update podman to 2.2.1

  - Update storage to 1.24.5

  - Switch to seccomp profile provided by common instead of podman

  - Update containers.conf to match latest version

     Changes in buildah:

     Update to version 1.19.2:

  * Update vendor of containers/storage and containers/common

  * Buildah inspect should be able to inspect manifests

  * Make buildah push support pushing manifests lists and digests

  * Fix handling of TMPDIR environment variable

  * Add support for --manifest flags

  * Upper directory should match mode of destination directory

  * Only grab the OS, Arch if the user actually specified them

  * Use --arch and --os and --variant options to select architecture and os

  * Cirrus: Track libseccomp and golang version

  * copier.PutOptions: add an 'IgnoreDevices' flag

  * fix: `rmi --prune` when parent image is in store.

  * Allow users to specify stdin into containers

  * Drop log message on failure to mount on /sys file systems to info

  * Spelling

  * SELinux no longer requires a tag.

  * Update nix pin with `make nixpkgs`

  * Switch references of /var/run -  /run

  * Allow FROM to be overridden with from option

  * copier: don&#x27 t assume we can chroot() on Unixy systems

  * copier: add PutOptions.NoOverwriteDirNonDir, Get/PutOptions.Rename

  * copier: handle replacing directories with not-directories

  * copier: Put: skip entries with zero-length names

  * Add U volume flag to chown source volumes

  * Turn off PRIOR_UBUNTU Test until vm is updated

  * pkg, cli: rootless uses correct isolation
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'buildah, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20210112~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~2.2.1~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.19.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~2.2.1~lp152.4.9.1", rls:"openSUSELeap15.2"))) {
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

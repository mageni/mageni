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
  script_oid("1.3.6.1.4.1.25623.1.0.854546");
  script_version("2022-03-24T14:03:56+0000");
  script_cve_id("CVE-2019-10214", "CVE-2020-10696", "CVE-2021-20206");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-01 13:18:00 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2022-03-23 08:27:48 +0000 (Wed, 23 Mar 2022)");
  script_name("openSUSE: Security Advisory for buildah (openSUSE-SU-2022:0770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0770-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WFIDXN6UAK2I4PPVFPBE4STNQH2FZQ4A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah'
  package(s) announced via the openSUSE-SU-2022:0770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:
  buildah was updated to version 1.23.1:
  Update to version 1.22.3:
  * Update dependencies
     * Post-branch commit
     * Accept repositories on login/logout
  Update to version 1.22.0:
  * c/image, c/storage, c/common vendor before Podman 3.3 release
     * Proposed patch for 3399 (shadowutils)
     * Fix handling of --restore shadow-utils
     * runtime-flag (debug) test: handle old &amp  new runc
     * Allow dst and destination for target in secret mounts
     * Multi-arch: Always push updated version-tagged img
     * imagebuildah.stageExecutor.prepare(): remove pseudonym check
     * refine dangling filter
     * Chown with environment variables not set should fail
     * Just restore protections of shadow-utils
     * Remove specific kernel version number requirement from install.md
     * Multi-arch image workflow: Make steps generic
     * chroot: fix environment value leakage to intermediate processes
     * Update nix pin with `make nixpkgs`
     * buildah source - create and manage source images
     * Update cirrus-cron notification GH workflow
     * Reuse code from containers/common/pkg/parse
     * Cirrus: Freshen VM images
     * Fix excludes exception beginning with / or ./
     * Fix syntax for --manifest example
     * vendor containers/common@main
     * Cirrus: Drop dependence on fedora-minimal
     * Adjust conformance-test error-message regex
     * Workaround appearance of differing debug messages
     * Cirrus: Install docker from package cache
     * Switch rusagelogfile to use options.Out
     * Turn stdio back to blocking when command finishes
     * Add support for default network creation
     * Cirrus: Updates for master- main rename
     * Change references from master to main
     * Add `--env` and `--workingdir` flags to run command
     * [CI:DOCS] buildah bud: spelling --ignore-file requires parameter
     * [CI:DOCS] push/pull: clarify supported transports
     * Remove unused function arguments
     * Create mountOptions for mount command flags
     * Extract version command implementation to function
     * Add --json flags to `mount` and `version` commands
     * copier.Put(): set xattrs after ownership
     * buildah add/copy: spelling
     * buildah copy and buildah add should support .containerignore
     * Remove unused util.StartsWithValidTransport
     * Fix documentation of the --format option of buildah push
     * Don't use alltransports.ParseImageName with known transports
     * man pages: clarify `rmi` removes dangling parents
     * [CI:DOCS] Fix links to c/image master bra ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'buildah' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.23.1~150300.8.3.1", rls:"openSUSELeap15.3"))) {
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

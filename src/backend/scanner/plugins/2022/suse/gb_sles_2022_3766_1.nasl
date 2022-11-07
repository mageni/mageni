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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3766.1");
  script_cve_id("CVE-2020-10696", "CVE-2021-20206", "CVE-2022-2990");
  script_tag(name:"creation_date", value:"2022-10-27 04:38:58 +0000 (Thu, 27 Oct 2022)");
  script_version("2022-10-27T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-10-27 10:11:07 +0000 (Thu, 27 Oct 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-01 13:18:00 +0000 (Wed, 01 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3766-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3766-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223766-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2022:3766-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

CVE-2021-20206: Fixed an issue in libcni that could allow an attacker to
 execute arbitrary binaries on the host (bsc#1181961).

CVE-2020-10696: Fixed an issue that could lead to files being
 overwritten during the image building process (bsc#1167864).

CVE-2022-2990: Fixed possible information disclosure and modification /
 bsc#1202812

Buildah was updated to version 1.27.1:

run: add container gid to additional groups

Add fix for CVE-2022-2990 / bsc#1202812


Update to version 1.27.0:

Don't try to call runLabelStdioPipes if spec.Linux is not set

build: support filtering cache by duration using --cache-ttl

build: support building from commit when using git repo as build context

build: clean up git repos correctly when using subdirs

integration tests: quote '?' in shell scripts

test: manifest inspect should have OCIv1 annotation

vendor: bump to c/common@87fab4b7019a

Failure to determine a file or directory should print an error

refactor: remove unused CommitOptions from generateBuildOutput

stage_executor: generate output for cases with no commit

stage_executor, commit: output only if last stage in build

Use errors.Is() instead of os.Is{Not,}Exist

Minor test tweak for podman-remote compatibility

Cirrus: Use the latest imgts container

imagebuildah: complain about the right Dockerfile

tests: don't try to wrap `nil` errors

cmd/buildah.commitCmd: don't shadow 'err'

cmd/buildah.pullCmd: complain about DecryptConfig/EncryptConfig

Fix a copy/paste error message

Fix a typo in an error message

build,cache: support pulling/pushing cache layers to/from remote sources

Update vendor of containers/(common, storage, image)

Rename chroot/run.go to chroot/run_linux.go

Don't bother telling codespell to skip files that don't exist

Set user namespace defaults correctly for the library

imagebuildah: optimize cache hits for COPY and ADD instructions

Cirrus: Update VM images w/ updated bats

docs, run: show SELinux label flag for cache and bind mounts

imagebuildah, build: remove undefined concurrent writes

bump github.com/opencontainers/runtime-tools

Add FreeBSD support for 'buildah info'

Vendor in latest containers/(storage, common, image)

Add freebsd cross build targets

Make the jail package build on 32bit platforms

Cirrus: Ensure the build-push VM image is labeled

GHA: Fix dynamic script filename

Vendor in containers/(common, storage, image)

Run codespell

Remove import of github.com/pkg/errors

Avoid using cgo in pkg/jail

Rename footypes to fooTypes for naming consistency

Move cleanupTempVolumes and cleanupRunMounts to run_common.go

Make the various run mounts work for FreeBSD

Move get{Bind,Tmpfs,Secret,SSH}Mount to run_common.go

Move runSetupRunMounts to run_common.go

Move cleanableDestinationListFromMounts to run_common.go

Make setupMounts and runSetupBuiltinVolumes work on FreeBSD

Move ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Containers 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error-debugsource", rpm:"libgpg-error-debugsource~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error-devel", rpm:"libgpg-error-devel~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error-devel-debuginfo", rpm:"libgpg-error-devel-debuginfo~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0", rpm:"libgpg-error0~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0-32bit", rpm:"libgpg-error0-32bit~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0-32bit-debuginfo", rpm:"libgpg-error0-32bit-debuginfo~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0-debuginfo", rpm:"libgpg-error0-debuginfo~1.42~150300.9.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.27.1~150300.8.11.1", rls:"SLES15.0SP3"))) {
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

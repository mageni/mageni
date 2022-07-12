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
  script_oid("1.3.6.1.4.1.25623.1.0.853444");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2020-25039", "CVE-2020-25040");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-22 03:00:46 +0000 (Tue, 22 Sep 2020)");
  script_name("openSUSE: Security Advisory for singularity (openSUSE-SU-2020:1497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1497-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00070.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'singularity'
  package(s) announced via the openSUSE-SU-2020:1497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for singularity fixes the following issues:

  New version 3.6.3, addresses the following security issues:

  - CVE-2020-25039, boo#1176705

  When a Singularity action command (run, shell, exec) is run with the
  fakeroot or user namespace option, Singularity will extract a container
  image to a temporary sandbox directory. Due to insecure permissions on the
  temporary directory it is possible for any user with access to the system
  to read the contents of the image. Additionally, if the image contains a
  world-writable file or directory, it is possible for a user to inject
  arbitrary content into the running container.

  - CVE-2020-25040, boo#1176707

  When a Singularity command that results in a container build operation
  is executed, it is possible for a user with access to the system to read
  the contents of the image during the build. Additionally, if the image
  contains a world-writable file or directory, it is possible for a user to
  inject arbitrary content into the running build, which in certain
  circumstances may enable arbitrary code execution during the build and/or
  when the built container is run.

  New version 3.6.2, new features / functionalities:

  - Add --force option to singularity delete for non-interactive workflows.

  - Support compilation with FORTIFY_SOURCE=2 and build in pie mode with
  fstack-protector enabled

  - Changed defaults / behaviours

  - Default to current architecture for singularity delete.

  - Bug Fixes

  - Respect current remote for singularity delete command.

  - Allow rw as a (noop) bind option.

  - Fix capability handling regression in overlay mount.

  - Fix LD_LIBRARY_PATH environment override regression with --nv/--rocm.

  - Fix environment variable duplication within singularity engine.

  - Use -user-xattrs for unsquashfs to avoid error with rootless
  extraction using unsquashfs 3.4

  - Correct --no-home message for 3.6 CWD behavior.

  - Don't fail if parent of cache dir not accessible.

  - Fix tests for Go 1.15 Ctty handling.

  - Fix additional issues with test images on ARM64.

  - Fix FUSE e2e tests to use container ssh_config.

  - Provide advisory message r.e. need for upper and work to exist in
  overlay images.

  - Use squashfs mem and processor limits in squashfs gzip check.

  - Ensure build destination path is not an empty string - do not
  overwrite CWD.

  - Don't unset PATH when interpreting legacy /environment files.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1497=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1497=1");

  script_tag(name:"affected", value:"'singularity' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"singularity", rpm:"singularity~3.6.3~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity-debuginfo", rpm:"singularity-debuginfo~3.6.3~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"singularity", rpm:"singularity~3.6.3~lp151.2.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity-debuginfo", rpm:"singularity-debuginfo~3.6.3~lp151.2.9.1", rls:"openSUSELeap15.1"))) {
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
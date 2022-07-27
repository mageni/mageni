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
  script_oid("1.3.6.1.4.1.25623.1.0.853287");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2020-13845", "CVE-2020-13846", "CVE-2020-13847");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-20 03:00:42 +0000 (Mon, 20 Jul 2020)");
  script_name("openSUSE: Security Advisory for singularity (openSUSE-SU-2020:1011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1011-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'singularity'
  package(s) announced via the openSUSE-SU-2020:1011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for singularity fixes the following issues:

  - New version 3.6.0. This version introduces a new signature format for
  SIF images, and changes to the signing / verification code to address
  the following security problems:

  - CVE-2020-13845, boo#1174150 In Singularity 3.x versions below 3.6.0,
  issues allow the ECL to be bypassed by a malicious user.

  - CVE-2020-13846, boo#1174148 In Singularity 3.5 the --all / -a option
  to singularity verify returns success even when some objects in a SIF
  container are not signed,
  or cannot be verified.

  - CVE-2020-13847, boo#1174152 In Singularity 3.x versions below 3.6.0,
  Singularity's sign and verify commands do not sign metadata found in
  the global header or data object descriptors of a SIF file, allowing
  an attacker to cause unexpected behavior. A signed container may
  verify successfully, even when it has been modified in ways that could
  be exploited to cause malicious behavior.

  - New features / functionalities

  - A new '--legacy-insecure' flag to verify allows verification of SIF
  signatures in the old, insecure format.

  - A new '-l / --logs' flag for instance list that shows the paths to
  instance STDERR / STDOUT log files.

  - The --json output of instance list now include paths to STDERR /
  STDOUT log files.

  - Singularity now supports the execution of minimal Docker/OCI
  containers that do not contain /bin/sh, e.g. docker://hello-world.

  - A new cache structure is used that is concurrency safe on a filesystem
  that supports atomic rename. If you downgrade to Singularity 3.5 or
  older after using 3.6 you will need to run singularity cache clean.

  - A plugin system rework adds new hook points that will allow the
  development of plugins that modify behavior of the runtime. An image
  driver concept is introduced for plugins to support new ways of
  handling image and
  overlay mounts. Plugins built for <=3.5 are not compatible with 3.6.

  - The --bind flag can now bind directories from a SIF or ext3 image into
  a container.

  - The --fusemount feature to mount filesystems to a container via FUSE
  drivers is now a supported feature (previously an experimental hidden
  flag).

  - This permits users to mount e.g. sshfs and cvmfs filesystems to the
  container at runtime.

  - A new -c/--config flag allows an alternative singularity.conf to be
  specified by the root user, or all users in an unprivileged
  installation.

  - A new --env flag allows container environment variables to be set via
  the Singularity command line.

  - A new --env-file flag allows container environment variables to be s ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'singularity' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"singularity", rpm:"singularity~3.6.0~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity-debuginfo", rpm:"singularity-debuginfo~3.6.0~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
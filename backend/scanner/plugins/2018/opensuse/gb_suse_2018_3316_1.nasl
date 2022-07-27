###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3316_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for singularity openSUSE-SU-2018:3316-1 (singularity)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852060");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-12021");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:40:23 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for singularity openSUSE-SU-2018:3316-1 (singularity)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00048.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'singularity'
  package(s) announced via the openSUSE-SU-2018:3316_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Singularity was updated to version 2.6.0,
  bringing features, bugfixes and security fixes.

  Security issues fixed:

  - CVE-2018-12021: Fixed access control on systems supporting overlay file
  system (boo#1100333).

  Highlights of 2.6.0:

  - Allow admin to specify a non-standard location for mksquashfs binary at
  build time with '--with-mksquashfs' option.

  - '--nv' can be made default with all action commands in singularity.conf

  - '--nv' can be controlled by env vars '$SINGULARITY_NV' and
  '$SINGULARITY_NV_OFF'

  - Restore shim init process for proper signal handling and child reaping
    when container is initiated in its own PID namespace

  - Add '-i' option to image.create to specify the inode ratio.

  - Bind '/dev/nvidia*' into the container when the '--nv' flag is used in
  conjunction with the '--contain' flag

  - Add '--no-home' option to not mount user $HOME if it is not the $CWD and
  'mount home = yes' is set.

  - Added support for OAUTH2 Docker registries like Azure Container Registry

  Highlights of 2.5.2:

  - a new `build` command was added to replace `create` + `bootstrap`

  - default image format is squashfs, eliminating the need to specify a size

  - a `localimage` can be used as a build base, including ext3, sandbox, and
  other squashfs images

  - singularity hub can now be used as a base with the uri

  - Restore docker-extract aufs whiteout handling that implements correct
  extraction of docker container layers.

  Bug fixes:

  - Fix 404 when using Arch Linux bootstrap

  - Fix environment variables clearing while starting instances

  - several more bug fixes, see CHANGELOG.md for details


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1223=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1223=1");

  script_tag(name:"affected", value:"singularity on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libsingularity1", rpm:"libsingularity1~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsingularity1-debuginfo", rpm:"libsingularity1-debuginfo~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"singularity", rpm:"singularity~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"singularity-debuginfo", rpm:"singularity-debuginfo~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"singularity-debugsource", rpm:"singularity-debugsource~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"singularity-devel", rpm:"singularity-devel~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

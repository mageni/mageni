###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mes52 MDVA-2011:009 (mes52)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-03/msg00007.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831347");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Update for mes52 MDVA-2011:009 (mes52)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mes52'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"mes52 on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"This is an upgrade bundle of packages incorporating various fixes
  for the upcoming Mandriva Enterprise Server 5.2 release:

  mandriva-release-2009.0-14.4mdvmes5.2:

  * mandriva release should be update to 5.2 release, with new major
  features.

  grub-0.97-30.1mdvmes5.2:

  * Change CFLAGS to disable stack protector (since gfxboot is tweaking
  stack and can crash it with protector enabled). Use -Os, used by
  Fedora since 2002.

  * Replace ext4 patch with the one from Fedora

  * Patches 23 / 24: allow to specify multiple initrd on a single boot

  * add fedora patch to support virtio partitions, fix #52397

  * add patches from ubuntu:
  o add support for uuid xxx instead of root (hdX, Y)
  o add support GPT (from Marco Gerards)
  o add patch varargs (since some changes are used by uuid patch)

  xz-5.0.0-0.1mdvmes5.2:

  * We need to have xz support on mes5.2 to be able to handle new
  packages from cooker or next product 2011.0

  ka-deploy-0.94.4-0.1mdvmes5.2:

  * add missing script udev_creation.sh

  * fix annoying bug to umount $CHROOT/dev

  * fix a lot of bugs in fstab, grub preparation, remove udev persistent
  rules on client node

  * remove all old scripts, cleaning the spec file

  * update ka script to support UUID, remove old mke2fs static binairie

  * don't use patch on 32b and 64b release (break the ka-d-client)

  * do not build with -m32, doesn't exist on arm and mips

  cpuset-1.5.5-0.1mdvmes5.2:

  * Fix for Issue#3: cset fails to create cpu sets if some cpus are
  offline
  Problem in cset.rescan() for maxcpu if root cpuset cpus are complex
  pattern due to offlining cpus.

  * Fix for Issue#2: Apply patch by mostroski to avoid exception if
  running tasks with non-existent uids

  * Apply patch submitted by Christopher Johnston to fix failure of
  finding cpusets in a case-sensitive manner.

  * BNC#558395 - cset couldn't delete cpu set

  * BNC#558399 - cset unable to move thread

  * Fixed failure to delete cpuset if tasks preset, cset now waits a
  little bit for tardy tasks to disappear

  * Removed output noise from popened taskset command

  * Added example init.d cset script in documentation directory

  * Fix bug #26: Cpuset does not function on machines with greater than
  16 CPUs");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"cpuset", rpm:"cpuset~1.5.5~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub", rpm:"grub~0.97~30.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grub-doc", rpm:"grub-doc~0.97~30.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ka-deploy-server", rpm:"ka-deploy-server~0.94.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ka-deploy-source-node", rpm:"ka-deploy-source-node~0.94.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblzma5", rpm:"liblzma5~5.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblzma-devel", rpm:"liblzma-devel~5.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-release-common", rpm:"mandriva-release-common~2009.0~14.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-release-Server", rpm:"mandriva-release-Server~2009.0~14.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xz", rpm:"xz~5.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ka-deploy", rpm:"ka-deploy~0.94.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-release", rpm:"mandriva-release~2009.0~14.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lzma5", rpm:"lib64lzma5~5.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lzma-devel", rpm:"lib64lzma-devel~5.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

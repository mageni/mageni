###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gfs2-utils CESA-2009:1337 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016151.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880785");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6552");
  script_name("CentOS Update for gfs2-utils CESA-2009:1337 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gfs2-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gfs2-utils on CentOS 5");
  script_tag(name:"insight", value:"The gfs2-utils package provides the user-space tools necessary to mount,
  create, maintain, and test GFS2 file systems.

  Multiple insecure temporary file use flaws were discovered in GFS2 user
  level utilities. A local attacker could use these flaws to overwrite an
  arbitrary file writable by a victim running those utilities (typically
  root) with the output of the utilities via a symbolic link attack.
  (CVE-2008-6552)

  This update also fixes the following bugs:

  * gfs2_fsck now properly detects and repairs problems with sequence numbers
  on GFS2 file systems.

  * GFS2 user utilities now use the file system UUID.

  * gfs2_grow now properly updates the file system size during operation.

  * gfs2_fsck now returns the proper exit codes.

  * gfs2_convert now properly frees blocks when removing free blocks up to
  height 2.

  * the gfs2_fsck manual page has been renamed to fsck.gfs2 to match current
  standards.

  * the 'gfs2_tool df' command now provides human-readable output.

  * mounting GFS2 file systems with the noatime or noquota option now works
  properly.

  * new capabilities have been added to the gfs2_edit tool to help in testing
  and debugging GFS and GFS2 issues.

  * the 'gfs2_tool df' command no longer segfaults on file systems with a
  block size other than 4k.

  * the gfs2_grow manual page no longer references the '-r' option, which has
  been removed.

  * the 'gfs2_tool unfreeze' command no longer hangs during use.

  * gfs2_convert no longer corrupts file systems when converting from GFS to
  GFS2.

  * gfs2_fsck no longer segfaults when encountering a block which is listed
  as both a data and stuffed directory inode.

  * gfs2_fsck can now fix file systems even if the journal is already locked
  for use.

  * a GFS2 file system's metadata is now properly copied with 'gfs2_edit
  savemeta' and 'gfs2_edit restoremeta'.

  * the gfs2_edit savemeta function now properly saves blocks of type 2.

  * 'gfs2_convert -vy' now works properly on the PowerPC architecture.

  * when mounting a GFS2 file system as '/', mount_gfs2 no longer fails after
  being unable to find the file system in '/proc/mounts'.

  * gfs2_fsck no longer segfaults when fixing 'EA leaf block type' problems.

  All gfs2-utils users should upgrade to this updated package, which resolves
  these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gfs2-utils", rpm:"gfs2-utils~0.1.62~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

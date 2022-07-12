###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gnome-vfs2 RHSA-2013:0131-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00014.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870884");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:29 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2009-2473");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for gnome-vfs2 RHSA-2013:0131-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-vfs2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"gnome-vfs2 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The gnome-vfs2 packages provide the GNOME Virtual File System, which is the
  foundation of the Nautilus file manager. neon is an HTTP and WebDAV client
  library embedded in the gnome-vfs2 packages.

  A denial of service flaw was found in the neon Extensible Markup Language
  (XML) parser. Visiting a malicious DAV server with an application using
  gnome-vfs2 (such as Nautilus) could possibly cause the application to
  consume an excessive amount of CPU and memory. (CVE-2009-2473)

  This update also fixes the following bugs:

  * When extracted from the Uniform Resource Identifier (URI), gnome-vfs2
  returned escaped file paths. If a path, as stored in the URI,
  contained non-ASCII characters or ASCII characters which are parsed as
  something other than a file path (for example, spaces), the escaped path
  was inaccurate. Consequently, files with the described type of URI could
  not be processed. With this update, gnome-vfs2 properly unescapes paths
  that are required for a system call. As a result, these paths are parsed
  properly. (BZ#580855)

  * In certain cases, the trash info file was populated by foreign
  entries, pointing to live data. Emptying the trash caused an accidental
  deletion of valuable data. With this update, a workaround has been applied
  in order to prevent the deletion. As a result, the accidental data loss is
  prevented, however further information is still gathered to fully fix this
  problem. (BZ#586015)
  ClearCase. This behavior significantly slowed down file operations. With
  this update, the unnecessary stat() operations have been limited. As a
  result, gnome-vfs2 user interfaces, such as Nautilus, are more responsive.
  (BZ#822817)

  All gnome-vfs2 users are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"gnome-vfs2", rpm:"gnome-vfs2~2.16.2~10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-vfs2-debuginfo", rpm:"gnome-vfs2-debuginfo~2.16.2~10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-vfs2-devel", rpm:"gnome-vfs2-devel~2.16.2~10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-vfs2-smb", rpm:"gnome-vfs2-smb~2.16.2~10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

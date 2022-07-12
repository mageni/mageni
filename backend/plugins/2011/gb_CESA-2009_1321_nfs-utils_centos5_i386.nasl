###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for nfs-utils CESA-2009:1321 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016148.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880676");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4552");
  script_name("CentOS Update for nfs-utils CESA-2009:1321 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"nfs-utils on CentOS 5");
  script_tag(name:"insight", value:"The nfs-utils package provides a daemon for the kernel NFS server and
  related tools.

  It was discovered that nfs-utils did not use tcp_wrappers correctly.
  Certain hosts access rules defined in '/etc/hosts.allow' and
  '/etc/hosts.deny' may not have been honored, possibly allowing remote
  attackers to bypass intended access restrictions. (CVE-2008-4552)

  This updated package also fixes the following bugs:

  * the 'LOCKD_TCPPORT' and 'LOCKD_UDPPORT' options in '/etc/sysconfig/nfs'
  were not honored: the lockd daemon continued to use random ports. With this
  update, these options are honored. (BZ#434795)

  * it was not possible to mount NFS file systems from a system that has
  the '/etc/' directory mounted on a read-only file system (this could occur
  on systems with an NFS-mounted root file system). With this update, it is
  possible to mount NFS file systems from a system that has '/etc/' mounted
  on a read-only file system. (BZ#450646)

  * arguments specified by 'STATDARG=' in '/etc/sysconfig/nfs' were removed
  by the nfslock init script, meaning the arguments specified were never
  passed to rpc.statd. With this update, the nfslock init script no longer
  removes these arguments. (BZ#459591)

  * when mounting an NFS file system from a host not specified in the NFS
  server's '/etc/exports' file, a misleading 'unknown host' error was logged
  on the server (the hostname lookup did not fail). With this update, a
  clearer error message is provided for these situations. (BZ#463578)

  * the nhfsstone benchmark utility did not work with NFS version 3 and 4.
  This update adds support to nhfsstone for NFS version 3 and 4. The new
  nhfsstone '-2', '-3', and '-4' options are used to select an NFS version
  (similar to nfsstat(8)). (BZ#465933)

  * the exportfs(8) manual page contained a spelling mistake, 'djando', in
  the EXAMPLES section. (BZ#474848)

  * in some situations the NFS server incorrectly refused mounts to hosts
  that had a host alias in a NIS netgroup. (BZ#478952)

  * in some situations the NFS client used its cache, rather than using
  the latest version of a file or directory from a given export. This update
  adds a new mount option, 'lookupcache=', which allows the NFS client to
  control how it caches files and directories. Note: The Red Hat Enterprise
  Linux 5.4 kernel update (the fourth regular update) must be installed in
  order to use the 'lookupcache=' option.

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.0.9~42.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

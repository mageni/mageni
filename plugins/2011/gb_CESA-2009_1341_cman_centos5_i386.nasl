###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for cman CESA-2009:1341 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016155.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880860");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4579", "CVE-2008-6552");
  script_name("CentOS Update for cman CESA-2009:1341 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cman'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"cman on CentOS 5");
  script_tag(name:"insight", value:"The Cluster Manager (cman) utility provides services for managing a Linux
  cluster.

  Multiple insecure temporary file use flaws were found in fence_apc_snmp and
  ccs_tool. A local attacker could use these flaws to overwrite an arbitrary
  file writable by a victim running those utilities (typically root) with
  the output of the utilities via a symbolic link attack. (CVE-2008-4579,
  CVE-2008-6552)

  Bug fixes:

  * a buffer could overflow if cluster.conf had more than 52 entries per
  block inside the 'cman' block. The limit is now 1024.

  * the output of the group_tool dump subcommands were NULL padded.

  * using device='' instead of label='' no longer causes qdiskd to
  incorrectly exit.

  * the IPMI fencing agent has been modified to time out after 10 seconds. It
  is also now possible to specify a different timeout value with the '-t'
  option.

  * the IPMI fencing agent now allows punctuation in passwords.

  * quickly starting and stopping the cman service no longer causes the
  cluster membership to become inconsistent across the cluster.

  * an issue with lock syncing caused 'receive_own from' errors to be logged
  to '/var/log/messages'.

  * an issue which caused gfs_controld to segfault when mounting hundreds of
  file systems has been fixed.

  * the LPAR fencing agent now properly reports status when an LPAR is in
  Open Firmware mode.

  * the LPAR fencing agent now works properly with systems using the
  Integrated Virtualization Manager (IVM).

  * the APC SNMP fencing agent now properly recognizes outletStatusOn and
  outletStatusOff return codes from the SNMP agent.

  * the WTI fencing agent can now connect to fencing devices with no
  password.

  * the rps-10 fencing agent now properly performs a reboot when run with no
  options.

  * the IPMI fencing agent now supports different cipher types with the '-C'
  option.

  * qdisk now properly scans devices and partitions.

  * cman now checks to see if a new node has state to prevent killing the
  first node during cluster setup.

  * 'service qdiskd start' now works properly.

  * the McData fence agent now works properly with the McData Sphereon 4500
  Fabric Switch.

  * the Egenera fence agent can now specify an SSH login name.

  * the APC fence agent now works with non-admin accounts when using the
  3.5.x firmware.

  * fence_xvmd now tries two methods to reboot a virtual machine.

  * connections to OpenAIS are now allowed from unprivileged CPG clients with
  the user and group of 'ais'.

  * groupd no longer allows the default fence d ...

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

  if ((res = isrpmvuln(pkg:"cman", rpm:"cman~2.0.115~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cman-devel", rpm:"cman-devel~2.0.115~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

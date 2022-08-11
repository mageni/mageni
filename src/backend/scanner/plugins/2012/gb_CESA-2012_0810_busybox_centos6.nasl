###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for busybox CESA-2012:0810 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018712.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881234");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:54:03 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2006-1168", "CVE-2011-2716");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for busybox CESA-2012:0810 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"busybox on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"BusyBox provides a single binary that includes versions of a large number
  of system commands, including a shell. This can be very useful for
  recovering from certain types of system failures, particularly those
  involving broken shared libraries.

  A buffer underflow flaw was found in the way the uncompress utility of
  BusyBox expanded certain archive files compressed using Lempel-Ziv
  compression. If a user were tricked into expanding a specially-crafted
  archive file with uncompress, it could cause BusyBox to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running BusyBox. (CVE-2006-1168)

  The BusyBox DHCP client, udhcpc, did not sufficiently sanitize certain
  options provided in DHCP server replies, such as the client hostname. A
  malicious DHCP server could send such an option with a specially-crafted
  value to a DHCP client. If this option's value was saved on the client
  system, and then later insecurely evaluated by a process that assumes the
  option is trusted, it could lead to arbitrary code execution with the
  privileges of that process. Note: udhcpc is not used on Red Hat Enterprise
  Linux by default, and no DHCP client script is provided with the busybox
  packages. (CVE-2011-2716)

  This update also fixes the following bugs:

  * Prior to this update, the 'findfs' command did not recognize Btrfs
  partitions. As a consequence, an error message could occur when dumping a
  core file. This update adds support for recognizing such partitions so
  the problem no longer occurs. (BZ#751927)

  * If the 'grep' command was used with the '-F' and '-i' options at the
  same time, the '-i' option was ignored. As a consequence, the 'grep -iF'
  command incorrectly performed a case-sensitive search instead of an
  insensitive search. A patch has been applied to ensure that the combination
  of the '-F' and '-i' options works as expected. (BZ#752134)

  * Prior to this update, the msh shell did not support the 'set -o pipefail'
  command. This update adds support for this command. (BZ#782018)

  * Previously, the msh shell could terminate unexpectedly with a
  segmentation fault when attempting to execute an empty command as a result
  of variable substitution (for example msh -c '$nonexistent_variable').
  With this update, msh has been modified to correctly interpret such
  commands and no longer crashes in this scenario. (BZ#809092)

  * Previously, the msh shell incorrectly executed empty loops. As a
  consequence, msh never exited such ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.15.1~15.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"busybox-petitboot", rpm:"busybox-petitboot~1.15.1~15.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

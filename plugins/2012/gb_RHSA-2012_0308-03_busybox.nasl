###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for busybox RHSA-2012:0308-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00048.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870557");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:56 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2006-1168", "CVE-2011-2716");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for busybox RHSA-2012:0308-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"busybox on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"BusyBox provides a single binary that includes versions of a large number
  of system commands, including a shell. This can be very useful for
  recovering from certain types of system failures, particularly those
  involving broken shared libraries.

  A buffer underflow flaw was found in the way the uncompress utility of
  BusyBox expanded certain archive files compressed using Lempel-Ziv
  compression. If a user were tricked into expanding a specially-crafted
  archive file with uncompress, it could cause BusyBox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  BusyBox. (CVE-2006-1168)

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

  * Prior to this update, the cp command wrongly returned the exit code 0 to
  indicate success if a device ran out of space while attempting to copy
  files of more than 4 gigabytes. This update modifies BusyBox, so that in
  such situations, the exit code 1 is returned. Now, the cp command shows
  correctly whether a process failed. (BZ#689659)

  * Prior to this update, the findfs command failed to check all existing
  block devices on a system with thousands of block device nodes in '/dev/'.
  This update modifies BusyBox so that findfs checks all block devices even
  in this case. (BZ#756723)

  All users of busybox are advised to upgrade to these updated packages,
  which correct these issues.");
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

  if ((res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.2.0~13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"busybox-anaconda", rpm:"busybox-anaconda~1.2.0~13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

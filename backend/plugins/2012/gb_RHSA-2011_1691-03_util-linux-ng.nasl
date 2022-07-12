###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for util-linux-ng RHSA-2011:1691-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00015.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870683");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:46:09 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for util-linux-ng RHSA-2011:1691-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux-ng'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"util-linux-ng on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The util-linux-ng packages contain a large variety of low-level system
  utilities that are necessary for a Linux operating system to function.

  Multiple flaws were found in the way the mount and umount commands
  performed mtab (mounted file systems table) file updates. A local,
  unprivileged user allowed to mount or unmount file systems could use these
  flaws to corrupt the mtab file and create a stale lock file, preventing
  other users from mounting and unmounting file systems. (CVE-2011-1675,
  CVE-2011-1677)

  This update also fixes the following bugs:

  * Due to a hard coded limit of 128 devices, an attempt to run the
  'blkid -c' command on more than 128 devices caused blkid to terminate
  unexpectedly. This update increases the maximum number of devices to 8192
  so that blkid no longer crashes in this scenario. (BZ#675999)

  * Previously, the 'swapon -a' command did not detect device-mapper
  devices that were already in use. This update corrects the swapon utility
  to detect such devices as expected. (BZ#679741)

  * Prior to this update, the presence of an invalid line in the /etc/fstab
  file could cause the umount utility to terminate unexpectedly with
  a segmentation fault. This update applies a patch that corrects this error
  so that umount now correctly reports invalid lines and no longer crashes.
  (BZ#684203)

  * Previously, an attempt to use the wipefs utility on a partitioned
  device caused the utility to terminate unexpectedly with an error. This
  update adapts wipefs to only display a warning message in this situation.
  (BZ#696959)

  * When providing information on interprocess communication (IPC)
  facilities, the ipcs utility could previously display a process owner as
  a negative number if the user's UID was too large. This update adapts the
  underlying source code to make sure the UID values are now displayed
  correctly. (BZ#712158)

  * In the installation scriptlets, the uuidd package uses the chkconfig
  utility to enable and disable the uuidd service. Previously, this package
  did not depend on the chkconfig package, which could lead to errors during
  installation if chkconfig was not installed. This update adds chkconfig
  to the list of dependencies so that such errors no longer occur.
  (BZ#712808)

  * The previous version of the /etc/udev/rules.d/60-raw.rules file
  contained a statement that both this file and raw devices are deprecated.
  This is no longer true and the Red Hat ...

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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libblkid", rpm:"libblkid~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuuid", rpm:"libuuid~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"util-linux-ng", rpm:"util-linux-ng~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"util-linux-ng-debuginfo", rpm:"util-linux-ng-debuginfo~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.17.2~12.4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

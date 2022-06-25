###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xorg-x11-server RHSA-2012:0303-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00057.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870548");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:14 +0530 (Tue, 21 Feb 2012)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-4028");
  script_name("RedHat Update for xorg-x11-server RHSA-2012:0303-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"xorg-x11-server on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"X.Org is an open source implementation of the X Window System. It provides
  the basic low-level functionality that full-fledged graphical user
  interfaces are designed upon.

  A flaw was found in the way the X.Org server handled lock files. A local
  user with access to the system console could use this flaw to determine the
  existence of a file in a directory not accessible to the user, via a
  symbolic link attack. (CVE-2011-4028)

  Red Hat would like to thank the researcher with the nickname vladz for
  reporting this issue.

  This update also fixes the following bugs:

  * In rare cases, if the front and back buffer of the miDbePositionWindow()
  function were not both allocated in video memory, or were both allocated in
  system memory, the X Window System sometimes terminated unexpectedly. A
  patch has been provided to address this issue and X no longer crashes in
  the described scenario. (BZ#596899)

  * Previously, when the miSetShape() function called the miRegionDestroy()
  function with a NULL region, X terminated unexpectedly if the backing store
  was enabled. Now, X no longer crashes in the described scenario.
  (BZ#676270)

  * On certain workstations running in 32-bit mode, the X11 mouse cursor
  occasionally became stuck near the left edge of the X11 screen. A patch has
  been provided to address this issue and the mouse cursor no longer becomes
  stuck in the described scenario. (BZ#529717)

  * On certain workstations with a dual-head graphics adapter using the r500
  driver in Zaphod mode, the mouse pointer was confined to one monitor screen
  and could not move to the other screen. A patch has been provided to
  address this issue and the mouse cursor works properly across both screens.
  (BZ#559964)

  * Due to a double free operation, Xvfb (X virtual framebuffer) terminated
  unexpectedly with a segmentation fault randomly when the last client
  disconnected, that is when the server reset. This bug has been fixed in the
  miDCCloseScreen() function and Xvfb no longer crashes. (BZ#674741)

  * Starting the Xephyr server on an AMD64 or Intel 64 architecture with an
  integrated graphics adapter caused the server to terminate unexpectedly.
  This bug has been fixed in the code and Xephyr no longer crashes in the
  described scenario. (BZ#454409)

  * Previously, when a client made a request bigger than 1/4th of the limit
  advertised in the BigRequestsEnable reply, the X server closed the
  connection unexpectedly. With this update, the maxBigRequestSize variable
  has been added to the code to check the size  ...

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

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvnc-source", rpm:"xorg-x11-server-Xvnc-source~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.90.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

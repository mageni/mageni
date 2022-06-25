###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xorg-x11-server-common CESA-2012:0939 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018722.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881153");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:24:06 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4028", "CVE-2011-4029");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for xorg-x11-server-common CESA-2012:0939 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-common'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"xorg-x11-server-common on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"X.Org is an open source implementation of the X Window System. It provides
  the basic low-level functionality that full-fledged graphical user
  interfaces are designed upon.

  A flaw was found in the way the X.Org server handled lock files. A local
  user with access to the system console could use this flaw to determine the
  existence of a file in a directory not accessible to the user, via a
  symbolic link attack. (CVE-2011-4028)

  A race condition was found in the way the X.Org server managed temporary
  lock files. A local attacker could use this flaw to perform a symbolic link
  attack, allowing them to make an arbitrary file world readable, leading to
  the disclosure of sensitive information. (CVE-2011-4029)

  Red Hat would like to thank the researcher with the nickname vladz for
  reporting these issues.

  This update also fixes the following bugs:

  * Prior to this update, the KDE Display Manager (KDM) could pass invalid
  24bpp pixmap formats to the X server. As a consequence, the X server could
  unexpectedly abort. This update modifies the underlying code to pass the
  correct formats. (BZ#651934, BZ#722860)

  * Prior to this update, absolute input devices, like the stylus of a
  graphic tablet, could become unresponsive in the right-most or bottom-most
  screen if the X server was configured as a multi-screen setup through
  multiple 'Device' sections in the xorg.conf file. This update changes the
  screen crossing behavior so that absolute devices are always mapped across
  all screens. (BZ#732467)

  * Prior to this update, the misleading message 'Session active, not
  inhibited, screen idle. If you see this test, your display server is broken
  and you should notify your distributor.' could be displayed after resuming
  the system or re-enabling the display, and included a URL to an external
  web page. This update removes this message. (BZ#748704)

  * Prior to this update, the erroneous input handling code of the Xephyr
  server disabled screens on a screen crossing event. The focus was only on
  the screen where the mouse was located and only this screen was updated
  when the Xephyr nested X server was configured in a multi-screen setup.
  This update removes this code and Xephyr now correctly updates screens in
  multi-screen setups. (BZ#757792)

  * Prior to this update, raw events did not contain relative axis values. As
  a consequence, clients which relied on relative values for functioning did
  not behave as expected. This update sets the values to the original driver
  values instead of the already transf ...

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

  if ((res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-devel", rpm:"xorg-x11-server-devel~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-source", rpm:"xorg-x11-server-source~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.10.6~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gtk2 CESA-2013:0135 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019150.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881573");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:45 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2012-2370");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for gtk2 CESA-2013:0135 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gtk2 on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"GIMP Toolkit (GTK+) is a multi-platform toolkit for creating graphical user
  interfaces.

  An integer overflow flaw was found in the X BitMap (XBM) image file loader
  in GTK+. A remote attacker could provide a specially-crafted XBM image file
  that, when opened in an application linked against GTK+ (such as Nautilus),
  would cause the application to crash. (CVE-2012-2370)

  This update also fixes the following bugs:

  * Due to a bug in the Input Method GTK+ module, the usage of the Taiwanese
  Big5 (zh_TW.Big-5) locale led to the unexpected termination of certain
  applications, such as the GDM greeter. The bug has been fixed, and the
  Taiwanese locale no longer causes applications to terminate unexpectedly.
  (BZ#487630)

  * When a file was initially selected after the GTK+ file chooser dialog was
  opened and the Location field was visible, pressing the Enter key did not
  open the file. With this update, the initially selected file is opened
  regardless of the visibility of the Location field. (BZ#518483)

  * When a file was initially selected after the GTK+ file chooser dialog was
  opened and the Location field was visible, pressing the Enter key did not
  change into the directory. With this update, the dialog changes into the
  initially selected directory regardless of the visibility of the Location
  field. (BZ#523657)

  * Previously, the GTK Print dialog did not reflect the user-defined printer
  preferences stored in the ~/.cups/lpoptions file, such as those set in the
  Default Printer preferences panel. Consequently, the first device in the
  printer list was always set as a default printer. With this update, the
  underlying source code has been enhanced to parse the option file. As a
  result, the default values in the print dialog are set to those previously
  specified by the user. (BZ#603809)

  * The GTK+ file chooser did not properly handle saving of nameless files.
  Consequently, attempting to save a file without specifying a file name
  caused GTK+ to become unresponsive. With this update, an explicit test for
  this condition has been added into the underlying source code. As a result,
  GTK+ no longer hangs in the described scenario. (BZ#702342)

  * When using certain graphics tablets, the GTK+ library incorrectly
  translated the input coordinates. Consequently, an offset occurred between
  the position of the pen and the content drawn on the screen. This issue was
  limited to the following configuration: a Wacom tablet with input
  coordinates bound to a single monitor in a dual head configuration, drawing
  with a pen with the pressure sens ...

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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gtk2", rpm:"gtk2~2.10.4~29.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gtk2-devel", rpm:"gtk2-devel~2.10.4~29.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for GNOME Shell RHSA-2015:0535-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871322");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:49:02 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-7300");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for GNOME Shell RHSA-2015:0535-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'GNOME Shell'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"GNOME Shell and the packages it depends upon provide the core user
interface of the Red Hat Enterprise Linux desktop, including functions such
as navigating between windows and launching applications.

It was found that the GNOME shell did not disable the Print Screen key when
the screen was locked. This could allow an attacker with physical access to
a system with a locked screen to crash the screen-locking application by
creating a large amount of screenshots. (CVE-2014-7300)

This update also fixes the following bugs:

  * The Timed Login feature, which automatically logs in a specified user
after a specified period of time, stopped working after the first user of
the GUI logged out. This has been fixed, and the specified user is always
logged in if no one else logs in. (BZ#1043571)

  * If two monitors were arranged vertically with the secondary monitor above
the primary monitor, it was impossible to move windows onto the secondary
monitor. With this update, windows can be moved through the upper edge of
the first monitor to the secondary monitor. (BZ#1075240)

  * If the Gnome Display Manager (GDM) user list was disabled and a user
entered the user name, the password prompt did not appear. Instead, the
user had to enter the user name one more time. The GDM code that contained
this error has been fixed, and users can enter their user names and
passwords as expected. (BZ#1109530)

  * Prior to this update, only a small area was available on the GDM login
screen for a custom text banner. As a consequence, when a long banner was
used, it did not fit into the area, and the person reading the banner had
to use scrollbars to view the whole text. With this update, more space is
used for the banner if necessary, which allows the user to read the message
conveniently. (BZ#1110036)

  * When the Cancel button was pressed while an LDAP user name and password
was being validated, the GDM code did not handle the situation correctly.
As a consequence, GDM became unresponsive, and it was impossible to return
to the login screen. The affected code has been fixed, and LDAP user
validation can be canceled, allowing another user to log in instead.
(BZ#1137041)

  * If the window focus mode in GNOME was set to 'mouse' or 'sloppy',
navigating through areas of a pop-up menu displayed outside its parent
window caused the window to lose its focus. Consequently, the menu was not
usable. This has been fixed, and the window focus is kept in under this
scenario. (BZ#1149585)

  * If user authentication is configured to require a smart card to log in,
user names are obtained from the smart card. The a ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"GNOME Shell on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00009.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"clutter", rpm:"clutter~1.14.4~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clutter-debuginfo", rpm:"clutter-debuginfo~1.14.4~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cogl", rpm:"cogl~1.14.0~6.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cogl-debuginfo", rpm:"cogl-debuginfo~1.14.0~6.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.8.4~45.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-shell-debuginfo", rpm:"gnome-shell-debuginfo~3.8.4~45.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutter", rpm:"mutter~3.8.4~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutter-debuginfo", rpm:"mutter-debuginfo~3.8.4~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

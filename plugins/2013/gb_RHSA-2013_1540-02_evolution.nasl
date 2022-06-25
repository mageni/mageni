###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for evolution RHSA-2013:1540-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871074");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:43:56 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-4166");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for evolution RHSA-2013:1540-02");


  script_tag(name:"affected", value:"evolution on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Evolution is the integrated collection of email, calendaring, contact
management, communications, and personal information management (PIM) tools
for the GNOME desktop environment.

A flaw was found in the way Evolution selected GnuPG public keys when
encrypting emails. This could result in emails being encrypted with public
keys other than the one belonging to the intended recipient.
(CVE-2013-4166)

The Evolution packages have been upgraded to upstream version 2.32.3, which
provides a number of bug fixes and enhancements over the previous version.
These changes include implementation of Gnome XDG Config Folders, and
support for Exchange Web Services (EWS) protocol to connect to Microsoft
Exchange servers. EWS support has been added as a part of the
evolution-exchange packages. (BZ#883010, BZ#883014, BZ#883015, BZ#883017,
BZ#524917, BZ#524921, BZ#883044)

The gtkhtml3 packages have been upgraded to upstream version 2.32.2, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#883019)

The libgdata packages have been upgraded to upstream version 0.6.4, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#883032)

This update also fixes the following bug:

  * The Exchange Calendar could not fetch the 'Free' and 'Busy' information
for meeting attendees when using Microsoft Exchange 2010 servers, and this
information thus could not be displayed. This happened because Microsoft
Exchange 2010 servers use more strict rules for 'Free' and 'Busy'
information fetching. With this update, the respective code in the
openchange packages has been modified so the 'Free' and 'Busy' information
fetching now complies with the fetching rules on Microsoft Exchange 2010
servers. The 'Free' and 'Busy' information can now be displayed as expected
in the Exchange Calendar. (BZ#665967)

All Evolution users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements. All running instances of Evolution must be restarted for this
update to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00018.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"cheese", rpm:"cheese~2.28.1~8.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cheese-debuginfo", rpm:"cheese-debuginfo~2.28.1~8.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"control-center", rpm:"control-center~2.28.1~39.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"control-center-debuginfo", rpm:"control-center-debuginfo~2.28.1~39.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"control-center-extra", rpm:"control-center-extra~2.28.1~39.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"control-center-filesystem", rpm:"control-center-filesystem~2.28.1~39.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ekiga", rpm:"ekiga~3.2.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ekiga-debuginfo", rpm:"ekiga-debuginfo~3.2.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.32.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.32.3~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-data-server-debuginfo", rpm:"evolution-data-server-debuginfo~2.32.3~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~2.32.3~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.32.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-exchange", rpm:"evolution-exchange~2.32.3~16.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-exchange-debuginfo", rpm:"evolution-exchange-debuginfo~2.32.3~16.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-mapi", rpm:"evolution-mapi~0.32.2~12.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-mapi-debuginfo", rpm:"evolution-mapi-debuginfo~0.32.2~12.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-panel", rpm:"gnome-panel~2.30.2~15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-panel-debuginfo", rpm:"gnome-panel-debuginfo~2.30.2~15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-panel-libs", rpm:"gnome-panel-libs~2.30.2~15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-applet", rpm:"gnome-python2-applet~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-bugbuddy", rpm:"gnome-python2-bugbuddy~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-desktop", rpm:"gnome-python2-desktop~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-desktop-debuginfo", rpm:"gnome-python2-desktop-debuginfo~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-gnomekeyring", rpm:"gnome-python2-gnomekeyring~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-libwnck", rpm:"gnome-python2-libwnck~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-rsvg", rpm:"gnome-python2-rsvg~2.28.0~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gtkhtml3", rpm:"gtkhtml3~3.32.2~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gtkhtml3-debuginfo", rpm:"gtkhtml3-debuginfo~3.32.2~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdata", rpm:"libgdata~0.6.4~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdata-debuginfo", rpm:"libgdata-debuginfo~0.6.4~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdata-devel", rpm:"libgdata-devel~0.6.4~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nautilus-sendto", rpm:"nautilus-sendto~2.28.2~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nautilus-sendto-debuginfo", rpm:"nautilus-sendto-debuginfo~2.28.2~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openchange", rpm:"openchange~1.0~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openchange-debuginfo", rpm:"openchange-debuginfo~1.0~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.7.9~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"planner", rpm:"planner~0.14.4~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"planner-debuginfo", rpm:"planner-debuginfo~0.14.4~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem", rpm:"totem~2.28.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-debuginfo", rpm:"totem-debuginfo~2.28.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-mozplugin", rpm:"totem-mozplugin~2.28.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-nautilus", rpm:"totem-nautilus~2.28.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-upnp", rpm:"totem-upnp~2.28.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-data-server-doc", rpm:"evolution-data-server-doc~2.32.3~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-help", rpm:"evolution-help~2.32.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

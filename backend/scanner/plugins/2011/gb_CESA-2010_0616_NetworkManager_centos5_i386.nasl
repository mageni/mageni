###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for NetworkManager CESA-2010:0616 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-August/016900.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880609");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2010-1172");
  script_name("CentOS Update for NetworkManager CESA-2010:0616 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"NetworkManager on CentOS 5");
  script_tag(name:"insight", value:"dbus-glib is an add-on library to integrate the standard D-Bus library with
  the GLib main loop and threading model. NetworkManager is a network link
  manager that attempts to keep a wired or wireless network connection active
  at all times.

  It was discovered that dbus-glib did not enforce the 'access' flag on
  exported GObject properties. If such a property were read/write internally
  but specified as read-only externally, a malicious, local user could use
  this flaw to modify that property of an application. Such a change could
  impact the application's behavior (for example, if an IP address were
  changed the network may not come up properly after reboot) and possibly
  lead to a denial of service. (CVE-2010-1172)

  Due to the way dbus-glib translates an application's XML definitions of
  service interfaces and properties into C code at application build time,
  applications built against dbus-glib that use read-only properties needed
  to be rebuilt to fully fix the flaw. As such, this update provides
  NetworkManager packages that have been rebuilt against the updated
  dbus-glib packages. No other applications shipped with Red Hat Enterprise
  Linux 5 were affected.

  All dbus-glib and NetworkManager users are advised to upgrade to these
  updated packages, which contain a backported patch to correct this issue.
  Running instances of NetworkManager must be restarted (service
  NetworkManager restart) for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.7.0~10.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.7.0~10.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.7.0~10.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib-devel", rpm:"NetworkManager-glib-devel~0.7.0~10.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.7.0~10.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

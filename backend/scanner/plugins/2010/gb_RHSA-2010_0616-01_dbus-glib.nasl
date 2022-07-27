###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for dbus-glib RHSA-2010:0616-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "dbus-glib is an add-on library to integrate the standard D-Bus library with
  the GLib main loop and threading model. NetworkManager is a network link
  manager that attempts to keep a wired or wireless network connection active
  at all times.

  It was discovered that dbus-glib did not enforce the &quot;access&quot; flag on
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
  NetworkManager restart) for this update to take effect.";

tag_affected = "dbus-glib on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-August/msg00014.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313033");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-13 14:24:53 +0200 (Fri, 13 Aug 2010)");
  script_xref(name: "RHSA", value: "2010:0616-01");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2010-1172");
  script_name("RedHat Update for dbus-glib RHSA-2010:0616-01");

  script_tag(name: "summary" , value: "Check for the Version of dbus-glib");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.7.0~10.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-debuginfo", rpm:"NetworkManager-debuginfo~0.7.0~10.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.7.0~10.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.7.0~10.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib-devel", rpm:"NetworkManager-glib-devel~0.7.0~10.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.7.0~10.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-glib", rpm:"dbus-glib~0.73~10.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-glib-debuginfo", rpm:"dbus-glib-debuginfo~0.73~10.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-glib-devel", rpm:"dbus-glib-devel~0.73~10.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

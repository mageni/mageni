###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2128-01_gdm_and_gnome-session.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for gdm and gnome-session RHSA-2017:2128-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871863");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:48:00 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2015-7496");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for gdm and gnome-session RHSA-2017:2128-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm and gnome-session'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The GNOME Display Manager (GDM) provides the
  graphical login screen shown shortly after boot up, log out, and when
  user-switching. The following packages have been upgraded to a later upstream
  version: gdm (3.22.3), gnome-session (3.22.3). (BZ#1386862, BZ#1386957) Security
  Fix(es): * It was found that gdm could crash due to a signal handler dispatched
  to an invalid conversation. An attacker could crash gdm by holding the escape
  key when the screen is locked, possibly bypassing the locked screen.
  (CVE-2015-7496) Additional Changes: For detailed information on changes in this
  release, see the Red Hat Enterprise Linux 7.4 Release Notes linked from the
  References section.");
  script_tag(name:"affected", value:"gdm and gnome-session on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00027.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~3.22.3~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-debuginfo", rpm:"gdm-debuginfo~3.22.3~11.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-session", rpm:"gnome-session~3.22.3~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-session-debuginfo", rpm:"gnome-session-debuginfo~3.22.3~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-session-xsession", rpm:"gnome-session-xsession~3.22.3~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
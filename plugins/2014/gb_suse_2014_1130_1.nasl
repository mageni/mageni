###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1130_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for update openSUSE-SU-2014:1130-1 (update)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850611");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-16 06:01:49 +0200 (Tue, 16 Sep 2014)");
  script_cve_id("CVE-2014-0547", "CVE-2014-0548", "CVE-2014-0549", "CVE-2014-0550",
                "CVE-2014-0551", "CVE-2014-0552", "CVE-2014-0553", "CVE-2014-0554",
                "CVE-2014-0555", "CVE-2014-0556", "CVE-2014-0557", "CVE-2014-0559");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for update openSUSE-SU-2014:1130-1 (update)");
  script_tag(name:"insight", value:"Adobe Flash Player was updated to 11.2.202.406 (bnc#895856):

  * APSB14-21, CVE-2014-0547, CVE-2014-0548, CVE-2014-0549, CVE-2014-0550,
  CVE-2014-0551, CVE-2014-0552, CVE-2014-0553, CVE-2014-0554,
  CVE-2014-0555, CVE-2014-0556, CVE-2014-0557, CVE-2014-0559

  More information can be found on the referenced vendor advisory.");

  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-21.html");

  script_tag(name:"affected", value:"update on openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.406~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.406~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-kde4", rpm:"flash-player-kde4~11.2.202.406~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

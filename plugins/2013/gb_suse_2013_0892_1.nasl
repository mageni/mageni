###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_0892_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for flash-player openSUSE-SU-2013:0892-1 (flash-player)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850484");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:25 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-2728", "CVE-2013-3324", "CVE-2013-3325", "CVE-2013-3326",
                "CVE-2013-3327", "CVE-2013-3328", "CVE-2013-3329", "CVE-2013-3330",
                "CVE-2013-3331", "CVE-2013-3332", "CVE-2013-3333", "CVE-2013-3334",
                "CVE-2013-3335");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for flash-player openSUSE-SU-2013:0892-1 (flash-player)");
  script_tag(name:"affected", value:"flash-player on openSUSE 11.4");
  script_tag(name:"insight", value:"flash-player was updated to security update to 11.2.202.285:

  * APSB13-14, CVE-2013-2728, CVE-2013-3324, CVE-2013-3325,
  CVE-2013-3326, CVE-2013-3327, CVE-2013-3328,
  CVE-2013-3329, CVE-2013-3330, CVE-2013-3331,
  CVE-2013-3332, CVE-2013-3333, CVE-2013-3334, CVE-2013-3335");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.285~63.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.285~63.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-kde4", rpm:"flash-player-kde4~11.2.202.285~63.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

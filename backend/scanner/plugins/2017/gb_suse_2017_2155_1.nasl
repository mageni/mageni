###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2155_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for tcmu-runner openSUSE-SU-2017:2155-1 (tcmu-runner)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851589");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-12 07:30:10 +0200 (Sat, 12 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for tcmu-runner openSUSE-SU-2017:2155-1 (tcmu-runner)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcmu-runner'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for tcmu-runner fixes the following issues:

  - qcow handler opens up an information leak via the CheckConfig D-Bus
  method (bsc#1049491)

  - glfs handler allows local DoS via crafted CheckConfig strings
  (bsc#1049485)

  - UnregisterHandler dbus method in tcmu-runner daemon for non-existing
  handler causes denial of service (bsc#1049488)

  - UnregisterHandler D-Bus method in tcmu-runner daemon for internal
  handler causes denial of service (bsc#1049489)

  - Memory leaks can be triggered in tcmu-runner daemon by calling D-Bus
  method for (Un)RegisterHandler (bsc#1049490)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.");
  script_tag(name:"affected", value:"tcmu-runner on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libtcmu-devel", rpm:"libtcmu-devel~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtcmu1", rpm:"libtcmu1~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtcmu1-debuginfo", rpm:"libtcmu1-debuginfo~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcmu-runner", rpm:"tcmu-runner~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcmu-runner-debuginfo", rpm:"tcmu-runner-debuginfo~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcmu-runner-debugsource", rpm:"tcmu-runner-debugsource~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcmu-runner-devel", rpm:"tcmu-runner-devel~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcmu-runner-handler-rbd", rpm:"tcmu-runner-handler-rbd~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcmu-runner-handler-rbd-debuginfo", rpm:"tcmu-runner-handler-rbd-debuginfo~1.2.0~3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

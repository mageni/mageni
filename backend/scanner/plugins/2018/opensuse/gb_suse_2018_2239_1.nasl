###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2239_1.nasl 13284 2019-01-25 08:13:29Z mmartin $
#
# SuSE Update for cups openSUSE-SU-2018:2239-1 (cups)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851838");
  script_version("$Revision: 13284 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 09:13:29 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-08-08 05:51:01 +0200 (Wed, 08 Aug 2018)");
  script_cve_id("CVE-2017-18248", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-4182",
  "CVE-2018-4183");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for cups openSUSE-SU-2018:2239-1 (cups)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for cups fixes the following issues:

  The following security vulnerabilities were fixed:

  - CVE-2017-18248: Handle invalid characters properly in printing jobs.
  This fixes a problem that was causing the DBUS library to abort the
  calling process. (bsc#1061066 bsc#1087018)

  - Fixed a local privilege escalation to root and sandbox bypasses in the
  scheduler

  - CVE-2018-4180: Fixed a local privilege escalation to root in dnssd
  backend (bsc#1096405)

  - CVE-2018-4181: Limited local file reads as root via cupsd.conf include
  directive (bsc#1096406)

  - CVE-2018-4182: Fixed a sandbox bypass due to insecure error handling
  (bsc#1096407)

  - CVE-2018-4183: Fixed a sandbox bypass due to profile misconfiguration
  (bsc#1096408)

  The following other issue was fixed:

  - Fixed authorization check for clients (like samba) connected through the
  local socket when Kerberos authentication is enabled (bsc#1050082)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-822=1");
  script_tag(name:"affected", value:"cups on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00022.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-ddk-debuginfo", rpm:"cups-ddk-debuginfo~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs-debuginfo", rpm:"cups-libs-debuginfo~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs-debuginfo-32bit", rpm:"cups-libs-debuginfo-32bit~1.7.5~12.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1636_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ntp openSUSE-SU-2016:1636-1 (ntp)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851347");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-21 05:48:07 +0200 (Tue, 21 Jun 2016)");
  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956",
                "CVE-2016-4957");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ntp openSUSE-SU-2016:1636-1 (ntp)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p8 to fix five security issues.

  These security issues were fixed:

  - CVE-2016-4953: Bad authentication demobilizes ephemeral associations
  (bsc#982065).

  - CVE-2016-4954: Processing spoofed server packets (bsc#982066).

  - CVE-2016-4955: Autokey association reset (bsc#982067).

  - CVE-2016-4956: Broadcast interleave (bsc#982068).

  - CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

  These non-security issues were fixed:

  - Keep the parent process alive until the daemon has finished
  initialisation, to make sure that the PID file exists when the parent
  returns.

  - bsc#979302: Change the process name of the forking DNS worker process to
  avoid the impression that ntpd is started twice.

  - bsc#981422: Don't ignore SIGCHILD because it breaks wait().

  - bsc#979981: ntp-wait does not accept fractional seconds, so use 1
  instead of 0.2 in ntp-wait.service.

  - Separate the creation of ntp.keys and key #1 in it to avoid problems
  when upgrading installations that have the file, but no key #1, which is
  needed e.g. by 'rcntp addserver'.

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");
  script_tag(name:"affected", value:"ntp on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~24.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p8~24.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p8~24.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~24.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

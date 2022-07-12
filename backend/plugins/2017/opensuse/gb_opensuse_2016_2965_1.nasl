###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2965_1.nasl 13012 2019-01-10 08:11:33Z asteins $
#
# SuSE Update for pacemaker openSUSE-SU-2016:2965-1 (pacemaker)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851502");
  script_version("$Revision: 13012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-10 09:11:33 +0100 (Thu, 10 Jan 2019) $");
  script_tag(name:"creation_date", value:"2017-02-22 15:16:00 +0100 (Wed, 22 Feb 2017)");
  script_cve_id("CVE-2016-7035", "CVE-2016-7797");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for pacemaker openSUSE-SU-2016:2965-1 (pacemaker)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacemaker'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for pacemaker fixes the following issues:

  Security issues fixed:

  - CVE-2016-7797: Notify other clients of a new connection only if the
  handshake has completed (bsc#967388, bsc#1002767).

  - CVE-2016-7035: Fixed improper IPC guarding in pacemaker (bsc#1007433).

  Bug fixes:

  - bsc#1003565: crmd: Record pending operations in the CIB before they are
  performed

  - bsc#1000743: pengine: Do not fence a maintenance node if it shuts down
  cleanly

  - bsc#987348: ping: Avoid temporary files for fping check

  - bsc#986644: libcrmcommon: report errors consistently when waiting for
  data on connection

  - bsc#986644: remote: Correctly calculate the remaining timeouts when
  receiving messages

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");
  script_tag(name:"affected", value:"pacemaker on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"libpacemaker-devel", rpm:"libpacemaker-devel~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpacemaker3", rpm:"libpacemaker3~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpacemaker3-debuginfo", rpm:"libpacemaker3-debuginfo~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker", rpm:"pacemaker~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cli", rpm:"pacemaker-cli~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cli-debuginfo", rpm:"pacemaker-cli-debuginfo~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cts", rpm:"pacemaker-cts~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cts-debuginfo", rpm:"pacemaker-cts-debuginfo~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-debuginfo", rpm:"pacemaker-debuginfo~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-debugsource", rpm:"pacemaker-debugsource~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-remote", rpm:"pacemaker-remote~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-remote-debuginfo", rpm:"pacemaker-remote-debuginfo~1.1.15~5.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2335_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libzypp openSUSE-SU-2017:2335-1 (libzypp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851606");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-03 07:19:00 +0200 (Sun, 03 Sep 2017)");
  script_cve_id("CVE-2017-7435", "CVE-2017-7436", "CVE-2017-9269");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libzypp openSUSE-SU-2017:2335-1 (libzypp)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Software Update Stack was updated to receive fixes and enhancements.

  libzypp:

  - CVE-2017-7435, CVE-2017-7436, CVE-2017-9269: Fix GPG check workflows,
  mainly for unsigned repositories and packages. (bsc#1045735, bsc#1038984)

  - Fix gpg-pubkey release (creation time) computation. (bsc#1036659)

  - Update lsof blacklist. (bsc#1046417)

  - Re-probe on refresh if the repository type changes. (bsc#1048315)

  - Propagate proper error code to DownloadProgressReport. (bsc#1047785)

  - Allow to trigger an appdata refresh unconditionally. (bsc#1009745)

  - Support custom repo variables defined in /etc/zypp/vars.d.

  yast2-pkg-bindings:

  - Do not crash when the repository URL is not defined. (bsc#1043218)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.");
  script_tag(name:"affected", value:"libzypp on openSUSE Leap 42.3");
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

  if ((res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.15.3~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~16.15.3~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~16.15.3~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~16.15.3~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-devel-doc", rpm:"libzypp-devel-doc~16.15.3~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-pkg-bindings", rpm:"yast2-pkg-bindings~3.2.4~4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-pkg-bindings-debuginfo", rpm:"yast2-pkg-bindings-debuginfo~3.2.4~4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-pkg-bindings-debugsource", rpm:"yast2-pkg-bindings-debugsource~3.2.4~4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-pkg-bindings-devel-doc", rpm:"yast2-pkg-bindings-devel-doc~3.2.4~4.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

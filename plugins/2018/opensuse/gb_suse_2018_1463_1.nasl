###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1463_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for perl-DBD-mysql openSUSE-SU-2018:1463-1 (perl-DBD-mysql)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851770");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-05-30 05:47:42 +0200 (Wed, 30 May 2018)");
  script_cve_id("CVE-2017-10788", "CVE-2017-10789", "CVE-2015-3152");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for perl-DBD-mysql openSUSE-SU-2018:1463-1 (perl-DBD-mysql)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBD-mysql'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for perl-DBD-mysql fixes the following issues:

  - CVE-2017-10789: The DBD::mysql module when with mysql_ssl is 1 setting
  enabled, means that SSL is optional (even though this setting's
  documentation has a 'your communication with the server will be
  encrypted' statement), which could lead man-in-the-middle attackers to
  spoof servers via a cleartext-downgrade attack, a related issue to
  CVE-2015-3152. (bsc#1047059)

  - CVE-2017-10788: The DBD::mysql module through 4.043 for Perl allows
  remote attackers to cause a denial of service (use-after-free and
  application crash) or possibly have unspecified other impact by
  triggering (1) certain error responses from a MySQL server or (2) a loss
  of a network connection to a MySQL server. The use-after-free defect was
  introduced by relying on incorrect Oracle mysql_stmt_close documentation
  and code examples. (bsc#1047095)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-539-1");
  script_tag(name:"affected", value:"perl-DBD-mysql on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-05/msg00113.html");
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

  if ((res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.021~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-DBD-mysql-debuginfo", rpm:"perl-DBD-mysql-debuginfo~4.021~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-DBD-mysql-debugsource", rpm:"perl-DBD-mysql-debugsource~4.021~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

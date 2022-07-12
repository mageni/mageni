###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0377_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MySQL openSUSE-SU-2016:0377-1 (MySQL)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851201");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-09 06:24:44 +0100 (Tue, 09 Feb 2016)");
  script_cve_id("CVE-2015-7744", "CVE-2016-0502", "CVE-2016-0503", "CVE-2016-0504",
                "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0594", "CVE-2016-0595",
                "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600",
                "CVE-2016-0605", "CVE-2016-0606", "CVE-2016-0607", "CVE-2016-0608",
                "CVE-2016-0609", "CVE-2016-0610", "CVE-2016-0611");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MySQL openSUSE-SU-2016:0377-1 (MySQL)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MySQL'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update to MySQL 5.6.28 fixes the following issues (bsc#962779):

  - CVE-2015-7744: Lack of verification against faults associated with the
  Chinese Remainder Theorem (CRT) process when allowing ephemeral key
  exchange without low memory optimizations on a server, which makes it
  easier for remote attackers to obtain private RSA keys by capturing TLS
  handshakes, aka a Lenstra attack.

  - CVE-2016-0502: Unspecified vulnerability in Oracle MySQL 5.5.31 and
  earlier and 5.6.11 and earlier allows remote authenticated users to
  affect availability via unknown vectors related to Optimizer.

  - CVE-2016-0503: Unspecified vulnerability in Oracle MySQL 5.6.27 and
  earlier and 5.7.9 allows remote authenticated users to affect
  availability via vectors related to DML, a different vulnerability than
  CVE-2016-0504.

  - CVE-2016-0504: Unspecified vulnerability in Oracle MySQL 5.6.27 and
  earlier and 5.7.9 allows remote authenticated users to affect
  availability via vectors related to DML, a different vulnerability than
  CVE-2016-0503.

  - CVE-2016-0505: Unspecified vulnerability in Oracle MySQL 5.5.46 and
  earlier, 5.6.27 and earlier, and 5.7.9 allows remote authenticated users
  to affect availability via unknown vectors related to Options.

  - CVE-2016-0546: Unspecified vulnerability in Oracle MySQL 5.5.46 and
  earlier, 5.6.27 and earlier, and 5.7.9 allows local users to affect
  confidentiality, integrity, and availability via unknown vectors related
  to Client.

  - CVE-2016-0594: Unspecified vulnerability in Oracle MySQL 5.6.21 and
  earlier allows remote authenticated users to affect availability via
  vectors related to DML.

  - CVE-2016-0595: Unspecified vulnerability in Oracle MySQL 5.6.27 and
  earlier allows remote authenticated users to affect availability via
  vectors related to DML.

  - CVE-2016-0596: Unspecified vulnerability in Oracle MySQL 5.5.46 and
  earlier and 5.6.27 and earlier allows remote authenticated users to
  affect availability via vectors related to DML.

  - CVE-2016-0597: Unspecified vulnerability in Oracle MySQL 5.5.46 and
  earlier, 5.6.27 and earlier, and 5.7.9 allows remote authenticated users
  to affect availability via unknown vectors related to Optimizer.

  - CVE-2016-0598: Unspecified vulnerability in Oracle MySQL 5.5.46 and
  earlier, 5.6.27 and earlier, and 5.7.9 allows remote authenticated users
  to affect availability via vectors related to DML.

  - CVE-2016-0600: Unspecified vulnerability in Oracle MySQL 5.5.46 and
  earlier, 5.6.27 and earlier, and 5.7.9 allows remote authenticated users
  to affect availability via unknown vectors re ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"MySQL on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.28~7.16.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

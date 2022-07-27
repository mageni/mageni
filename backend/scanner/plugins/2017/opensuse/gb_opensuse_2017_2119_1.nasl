###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2119_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for mariadb openSUSE-SU-2017:2119-1 (mariadb)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851587");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-10 07:29:53 +0200 (Thu, 10 Aug 2017)");
  script_cve_id("CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3453", "CVE-2017-3456",
                "CVE-2017-3464");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mariadb openSUSE-SU-2017:2119-1 (mariadb)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This MariaDB update to version 10.0.31 GA fixes the following issues:

  Security issues fixed:

  - CVE-2017-3308: Subcomponent: Server: DML: Easily 'exploitable'
  vulnerability allows low privileged attacker with network access via
  multiple protocols to compromise MariaDB Server. Successful attacks of
  this vulnerability can result in unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS). (bsc#1048715)

  - CVE-2017-3309: Subcomponent: Server: Optimizer: Easily 'exploitable'
  vulnerability allows low privileged attacker with network access via
  multiple protocols to compromise MariaDB Server. Successful attacks of
  this vulnerability can result in unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS). (bsc#1048715)

  - CVE-2017-3453: Subcomponent: Server: Optimizer: Easily 'exploitable'
  vulnerability allows low privileged attacker with network access via
  multiple protocols to compromise MariaDB Server. Successful attacks of
  this vulnerability can result in unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS). (bsc#1048715)

  - CVE-2017-3456: Subcomponent: Server: DML: Easily 'exploitable'
  vulnerability allows low privileged attacker with network access via
  multiple protocols to compromise MariaDB Server. Successful attacks of
  this vulnerability can result in unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS). (bsc#1048715)

  - CVE-2017-3464: Subcomponent: Server: DDL: Easily 'exploitable'
  vulnerability allows low privileged attacker with network access via
  multiple protocols to compromise MariaDB Server. Successful attacks of
  this vulnerability can result in unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS). (bsc#1048715)

  Bug fixes:

  - switch from 'Restart=on-failure' to 'Restart=on-abort' in mysql.service
  in order to follow the upstream. It also fixes hanging
  mysql-systemd-helper when mariadb fails (e.g. because of the
  misconfiguration) (bsc#963041)

  - XtraDB updated to 5.6.36-82.0

  - TokuDB updated to 5.6.36-82.0

  - Innodb updated to 5.6.36

  - Performance Schema updated to 5.6.36

  Release notes and changelog are linked in the references.

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");
  script_tag(name:"affected", value:"mariadb on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");

  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10031-release-notes");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10031-changelog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"libmysqlclient-devel", rpm:"libmysqlclient-devel~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqld18", rpm:"libmysqld18~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqld18-debuginfo", rpm:"libmysqld18-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench-debuginfo", rpm:"mariadb-bench-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test-debuginfo", rpm:"mariadb-test-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r18-32bit", rpm:"libmysqlclient_r18-32bit~10.0.31~20.7.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0730_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for mariadb openSUSE-SU-2018:0730-1 (mariadb)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851719");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-18 08:38:43 +0100 (Sun, 18 Mar 2018)");
  script_cve_id("CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640",
                "CVE-2018-2665", "CVE-2018-2668");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mariadb openSUSE-SU-2018:0730-1 (mariadb)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

  MariaDB was updated to 10.0.34 (bsc#1078431)

  The following security vulnerabilities are fixed:

  - CVE-2018-2562: Vulnerability in the MySQL Server subcomponent: Server :
  Partition. Easily exploitable vulnerability allowed low privileged
  attacker with network access via multiple protocols to compromise MySQL
  Server. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server as well as unauthorized update, insert or
  delete access to some of MySQL Server accessible data.

  - CVE-2018-2622: Vulnerability in the MySQL Server subcomponent: Server:
  DDL. Easily exploitable vulnerability allowed low privileged attacker
  with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized
  ability to cause a hang or frequently repeatable crash (complete DOS) of
  MySQL Server.

  - CVE-2018-2640: Vulnerability in the MySQL Server subcomponent: Server:
  Optimizer. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server.

  - CVE-2018-2665: Vulnerability in the MySQL Server subcomponent: Server:
  Optimizer. Easily exploitable vulnerability allowed low privileged
  attacker with network access via multiple protocols to compromise MySQL
  Server. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server.

  - CVE-2018-2668: Vulnerability in the MySQL Server subcomponent: Server:
  Optimizer. Easily exploitable vulnerability allowed low privileged
  attacker with network access via multiple protocols to compromise MySQL
  Server. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server.

  - CVE-2018-2612: Vulnerability in the MySQL Server subcomponent: InnoDB.
  Easily exploitable vulnerability allowed high privileged attacker with
  network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized
  creation, deletion or modification access to critical data or all MySQL
  Server accessible data and unauthorized ability to cause a hang or
  frequently repeatable crash (complete DOS) of MySQL Server.


  The MariaDB external release notes and changelog for this release:

  * <a  rel='nofollow' hr ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"mariadb on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00046.html");
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

  if ((res = isrpmvuln(pkg:"libmysqlclient-devel", rpm:"libmysqlclient-devel~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqld18", rpm:"libmysqld18~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqld18-debuginfo", rpm:"libmysqld18-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench-debuginfo", rpm:"mariadb-bench-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test-debuginfo", rpm:"mariadb-test-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r18-32bit", rpm:"libmysqlclient_r18-32bit~10.0.34~32.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

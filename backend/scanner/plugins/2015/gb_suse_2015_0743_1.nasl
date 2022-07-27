###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0743_1.nasl 12858 2018-12-21 08:05:36Z ckuersteiner $
#
# SuSE Update for mariadb SUSE-SU-2015:0743-1 (mariadb)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850960");
  script_version("$Revision: 12858 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 09:05:36 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 15:04:16 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2010-5298", "CVE-2012-5615", "CVE-2014-0195", "CVE-2014-0198",
                "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-2494", "CVE-2014-3470",
                "CVE-2014-4207", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274",
                "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469",
                "CVE-2014-6474", "CVE-2014-6478", "CVE-2014-6484", "CVE-2014-6489",
                "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496",
                "CVE-2014-6500", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520",
                "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559",
                "CVE-2014-6564", "CVE-2014-6568", "CVE-2015-0374", "CVE-2015-0381",
                "CVE-2015-0382", "CVE-2015-0391", "CVE-2015-0411", "CVE-2015-0432");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mariadb SUSE-SU-2015:0743-1 (mariadb)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"mariadb was updated to version 10.0.16 to fix 40 security issues.

  These security issues were fixed:

  - CVE-2015-0411: Unspecified vulnerability in Oracle MySQL Server 5.5.40
  and earlier, and 5.6.21 and earlier, allowed remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors related
  to Server : Security : Encryption (bnc#915911).

  - CVE-2015-0382: Unspecified vulnerability in Oracle MySQL Server 5.5.40
  and earlier and 5.6.21 and earlier allowed remote attackers to affect
  availability via unknown vectors related to Server : Replication, a
  different vulnerability than CVE-2015-0381 (bnc#915911).

  - CVE-2015-0381: Unspecified vulnerability in Oracle MySQL Server 5.5.40
  and earlier and 5.6.21 and earlier allowed remote attackers to affect
  availability via unknown vectors related to Server : Replication, a
  different vulnerability than CVE-2015-0382 (bnc#915911).

  - CVE-2015-0432: Unspecified vulnerability in Oracle MySQL Server 5.5.40
  and earlier allowed remote authenticated users to affect availability
  via vectors related to Server : InnoDB : DDL : Foreign Key (bnc#915911).

  - CVE-2014-6568: Unspecified vulnerability in Oracle MySQL Server 5.5.40
  and earlier, and 5.6.21 and earlier, allowed remote authenticated users
  to affect availability via vectors related to Server : InnoDB : DML
  (bnc#915911).

  - CVE-2015-0374: Unspecified vulnerability in Oracle MySQL Server 5.5.40
  and earlier and 5.6.21 and earlier allowed remote authenticated users to
  affect confidentiality via unknown vectors related to Server : Security
  : Privileges : Foreign Key (bnc#915911).

  - CVE-2014-6507: Unspecified vulnerability in Oracle MySQL Server 5.5.39
  and earlier, and 5.6.20 and earlier, allowed remote authenticated users
  to affect confidentiality, integrity, and availability via vectors
  related to SERVER:DML (bnc#915912).

  - CVE-2014-6491: Unspecified vulnerability in Oracle MySQL Server 5.5.39
  and earlier and 5.6.20 and earlier allowed remote attackers to affect
  confidentiality, integrity, and availability via vectors related to
  SERVER:SSL:yaSSL, a different vulnerability than CVE-2014-6500
  (bnc#915912).

  - CVE-2014-6500: Unspecified vulnerability in Oracle MySQL Server 5.5.39
  and earlier, and 5.6.20 and earlier, allowed remote attackers to affect
  confidentiality, integrity, and availability via vectors related to
  SERVER:SSL:yaSSL, a different vulnerability than CVE-2014-6491
  (bnc#915912).

  - CVE-2014-6469: Unspecified vulnerability in Oracle MySQL Server 5.5.39
  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"mariadb on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r18-32bit", rpm:"libmysqlclient_r18-32bit~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.16~15.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.16~15.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

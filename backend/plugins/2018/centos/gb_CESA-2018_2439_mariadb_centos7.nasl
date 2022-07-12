###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2439_mariadb_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for mariadb CESA-2018:2439 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882940");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-21 06:42:25 +0200 (Tue, 21 Aug 2018)");
  script_cve_id("CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3651", "CVE-2017-3653", "CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for mariadb CESA-2018:2439 centos7");
  script_tag(name:"summary", value:"Check the version of mariadb");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MariaDB is a multi-user, multi-threaded SQL database server that is binary
compatible with MySQL.

The following packages have been upgraded to a later upstream version:
mariadb (5.5.60). (BZ#1584668, BZ#1584671, BZ#1584674, BZ#1601085)

Security Fix(es):

  * mysql: Client programs unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3636)

  * mysql: Server: DML unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3641)

  * mysql: Client mysqldump unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3651)

  * mysql: Server: Replication unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10268)

  * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10378)

  * mysql: Client programs unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10379)

  * mysql: Server: DDL unspecified vulnerability (CPU Oct 2017)
(CVE-2017-10384)

  * mysql: Server: Partition unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2562)

  * mysql: Server: DDL unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2622)

  * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2640)

  * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2665)

  * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2018)
(CVE-2018-2668)

  * mysql: Server: Replication unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2755)

  * mysql: Client programs unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2761)

  * mysql: Server: Locking unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2771)

  * mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2781)

  * mysql: Server: DDL unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2813)

  * mysql: Server: DDL unspecified vulnerability (CPU Apr 2018)
(CVE-2018-2817)

  * mysql: InnoDB unspecified vulnerability (CPU Apr 2018) (CVE-2018-2819)

  * mysql: Server: DDL unspecified vulnerability (CPU Jul 2017)
(CVE-2017-3653)

  * mysql: use of SSL/TLS not enforced in libmysqld (Return of BACKRONYM)
(CVE-2018-2767)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Bug Fix(es):

  * Previously, the mysqladmin tool waited for an inadequate length of time
if the socket it listened on did not respond in a specific way.
Consequently, when the socket was used while the MariaDB server was
starting, the mariadb service became unresponsive for a long time. With
this update, the mysqladmin timeout has been shortened to 2 seconds. As a
result, the mariadb service either starts or fails but no longer hangs in
the described situation. (BZ#1584023)");
  script_tag(name:"affected", value:"mariadb on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-August/022995.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-embedded", rpm:"mariadb-embedded~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-embedded-devel", rpm:"mariadb-embedded-devel~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.60~1.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
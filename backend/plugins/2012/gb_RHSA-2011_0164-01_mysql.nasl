###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2011:0164-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870736");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-05 19:32:48 +0530 (Tue, 05 Jun 2012)");
  script_cve_id("CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680",
                "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833",
                "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838",
                "CVE-2010-3839", "CVE-2010-3840");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for mysql RHSA-2011:0164-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"mysql on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  The MySQL PolyFromWKB() function did not sanity check Well-Known Binary
  (WKB) data, which could allow a remote, authenticated attacker to crash
  mysqld. (CVE-2010-3840)

  A flaw in the way MySQL processed certain JOIN queries could allow a
  remote, authenticated attacker to cause excessive CPU use (up to 100%), if
  a stored procedure contained JOIN queries, and that procedure was executed
  twice in sequence. (CVE-2010-3839)

  A flaw in the way MySQL processed queries that provide a mixture of numeric
  and longblob data types to the LEAST or GREATEST function, could allow a
  remote, authenticated attacker to crash mysqld. (CVE-2010-3838)

  A flaw in the way MySQL processed PREPARE statements containing both
  GROUP_CONCAT and the WITH ROLLUP modifier could allow a remote,
  authenticated attacker to crash mysqld. (CVE-2010-3837)

  MySQL did not properly pre-evaluate LIKE arguments in view prepare mode,
  possibly allowing a remote, authenticated attacker to crash mysqld.
  (CVE-2010-3836)

  A flaw in the way MySQL processed statements that assign a value to a
  user-defined variable and that also contain a logical value evaluation
  could allow a remote, authenticated attacker to crash mysqld.
  (CVE-2010-3835)

  A flaw in the way MySQL evaluated the arguments of extreme-value functions,
  such as LEAST and GREATEST, could allow a remote, authenticated attacker to
  crash mysqld. (CVE-2010-3833)

  A flaw in the way MySQL handled LOAD DATA INFILE requests allowed MySQL to
  send OK packets even when there were errors. (CVE-2010-3683)

  A flaw in the way MySQL processed EXPLAIN statements for some complex
  SELECT queries could allow a remote, authenticated attacker to crash
  mysqld. (CVE-2010-3682)

  A flaw in the way MySQL processed certain alternating READ requests
  provided by HANDLER statements could allow a remote, authenticated attacker
  to crash mysqld. (CVE-2010-3681)

  A flaw in the way MySQL processed CREATE TEMPORARY TABLE statements that
  define NULL columns when using the InnoDB storage engine, could allow a
  remote, authenticated attacker to crash mysqld. (CVE-2010-3680)

  A flaw in the way MySQL processed certain values provided to the BINLOG
  statement caused MySQL to read unassigned memory. A remote, authenticated
  attacker could possibly use this flaw to crash mysq ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-libs", rpm:"mysql-libs~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.1.52~1.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

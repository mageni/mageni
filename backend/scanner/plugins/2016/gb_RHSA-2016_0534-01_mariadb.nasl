###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mariadb RHSA-2016:0534-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871590");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-02 05:17:10 +0200 (Sat, 02 Apr 2016)");
  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816",
                "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836",
                "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879",
                "CVE-2015-4913", "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596",
                "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606",
                "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-2047");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mariadb RHSA-2016:0534-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MariaDB is a multi-user, multi-threaded SQL
database server that is binary compatible with MySQL.

The following packages have been upgraded to a newer upstream version:
MariaDB (5.5.47). Refer to the MariaDB Release Notes listed in the
References section for a complete list of changes.

Security Fix(es):

  * It was found that the MariaDB client library did not properly check host
names against server identities noted in the X.509 certificates when
establishing secure connections using TLS/SSL. A man-in-the-middle attacker
could possibly use this flaw to impersonate a server to a client.
(CVE-2016-2047)

  * This update fixes several vulnerabilities in the MariaDB database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory page, listed in the References section. (CVE-2015-4792,
CVE-2015-4802, CVE-2015-4815, CVE-2015-4816, CVE-2015-4819, CVE-2015-4826,
CVE-2015-4830, CVE-2015-4836, CVE-2015-4858, CVE-2015-4861, CVE-2015-4870,
CVE-2015-4879, CVE-2015-4913, CVE-2016-0505, CVE-2016-0546, CVE-2016-0596,
CVE-2016-0597, CVE-2016-0598, CVE-2016-0600, CVE-2016-0606, CVE-2016-0608,
CVE-2016-0609, CVE-2016-0616)

Bug Fix(es):

  * When more than one INSERT operation was executed concurrently on a
non-empty InnoDB table with an AUTO_INCREMENT column defined as a primary
key immediately after starting MariaDB, a race condition could occur. As a
consequence, one of the concurrent INSERT operations failed with a
'Duplicate key' error message. A patch has been applied to prevent the race
condition. Now, each row inserted as a result of the concurrent INSERT
operations receives a unique primary key, and the operations no longer fail
in this scenario. (BZ#1303946)");
  script_tag(name:"affected", value:"mariadb on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-April/msg00001.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.47~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

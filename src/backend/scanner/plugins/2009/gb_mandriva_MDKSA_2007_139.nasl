###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for MySQL MDKSA-2007:139 (MySQL)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "MySQL 5.x before 5.0.36 allows local users to cause a denial of service
  (database crash) by performing information_schema table subselects
  and using ORDER BY to sort a single-row result, which prevents
  certain structure elements from being initialized and triggers a
  NULL dereference in the filesort function. This issue does not affect
  MySQL 5.0.37 in Mandriva Linux 2007.1. (CVE-2007-1420)

  The in_decimal::set function in item_cmpfunc.cc in MySQL before 5.0.40,
  and 5.1 before 5.1.18-beta, allows context-dependent attackers to cause
  a denial of service (crash) via a crafted IF clause that results in
  a divide-by-zero error and a NULL pointer dereference. (CVE-2007-2583)
  
  MySQL before 4.1.23, 5.0.x before 5.0.42, and 5.1.x before 5.1.18
  does not require the DROP privilege for RENAME TABLE statements,
  which allows remote authenticated users to rename arbitrary
  tables. (CVE-2007-2691)
  
  Updated packages have been patched to prevent the above issues.";

tag_affected = "MySQL on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-07/msg00003.php");
  script_oid("1.3.6.1.4.1.25623.1.0.307126");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_xref(name: "MDKSA", value: "2007:139");
  script_cve_id("CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691");
  script_name( "Mandriva Update for MySQL MDKSA-2007:139 (MySQL)");

  script_tag(name:"summary", value:"Check for the Version of MySQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"MySQL", rpm:"MySQL~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-Max", rpm:"MySQL-Max~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-bench", rpm:"MySQL-bench~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-client", rpm:"MySQL-client~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-common", rpm:"MySQL-common~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-extra", rpm:"MySQL-ndb-extra~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-management", rpm:"MySQL-ndb-management~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-storage", rpm:"MySQL-ndb-storage~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-tools", rpm:"MySQL-ndb-tools~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql15", rpm:"libmysql15~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql15-devel", rpm:"libmysql15-devel~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql15-static-devel", rpm:"libmysql15-static-devel~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15", rpm:"lib64mysql15~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15-devel", rpm:"lib64mysql15-devel~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15-static-devel", rpm:"lib64mysql15-static-devel~5.0.37~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"MySQL", rpm:"MySQL~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-Max", rpm:"MySQL-Max~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-bench", rpm:"MySQL-bench~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-client", rpm:"MySQL-client~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-common", rpm:"MySQL-common~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-extra", rpm:"MySQL-ndb-extra~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-management", rpm:"MySQL-ndb-management~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-storage", rpm:"MySQL-ndb-storage~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MySQL-ndb-tools", rpm:"MySQL-ndb-tools~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql15", rpm:"libmysql15~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql15-devel", rpm:"libmysql15-devel~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql15-static-devel", rpm:"libmysql15-static-devel~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15", rpm:"lib64mysql15~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15-devel", rpm:"lib64mysql15-devel~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15-static-devel", rpm:"lib64mysql15-static-devel~5.0.24a~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

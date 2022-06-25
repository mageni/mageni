###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mysql MDVSA-2008:149 (mysql)
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
tag_insight = "Sergei Golubchik found that MySQL did not properly validate optional
  data or index directory paths given in a CREATE TABLE statement; as
  well it would not, under certain conditions, prevent two databases
  from using the same paths for data or index files.  This could allow
  an authenticated user with appropriate privilege to create tables in
  one database to read and manipulate data in tables later created in
  other databases, regardless of GRANT privileges (CVE-2008-2079).

  The updated packages have been patched to correct this issue.";

tag_affected = "mysql on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-07/msg00035.php");
  script_oid("1.3.6.1.4.1.25623.1.0.309781");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2008:149");
  script_cve_id("CVE-2008-2079");
  script_name( "Mandriva Update for mysql MDVSA-2008:149 (mysql)");

  script_tag(name:"summary", value:"Check for the Version of mysql");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"libmysql15", rpm:"libmysql15~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql-devel", rpm:"libmysql-devel~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql-static-devel", rpm:"libmysql-static-devel~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-common", rpm:"mysql-common~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-doc", rpm:"mysql-doc~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-max", rpm:"mysql-max~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-ndb-extra", rpm:"mysql-ndb-extra~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-ndb-management", rpm:"mysql-ndb-management~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-ndb-storage", rpm:"mysql-ndb-storage~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-ndb-tools", rpm:"mysql-ndb-tools~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql15", rpm:"lib64mysql15~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql-devel", rpm:"lib64mysql-devel~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mysql-static-devel", rpm:"lib64mysql-static-devel~5.0.51a~8.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

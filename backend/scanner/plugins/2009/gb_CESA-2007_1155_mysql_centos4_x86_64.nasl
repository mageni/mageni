###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mysql CESA-2007:1155 centos4 x86_64
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
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld), and
  many different client programs and libraries.

  A flaw was found in a way MySQL handled symbolic links when database tables
  were created with explicit &quot;DATA&quot; and &quot;INDEX DIRECTORY&quot; options. An
  authenticated user could create a table that would overwrite tables in
  other databases, causing destruction of data or allowing the user to
  elevate privileges. (CVE-2007-5969)
  
  A flaw was found in a way MySQL's InnoDB engine handled spatial indexes. An
  authenticated user could create a table with spatial indexes, which are not
  supported by the InnoDB engine, that would cause the mysql daemon to crash
  when used. This issue only causes a temporary denial of service, as the
  mysql daemon will be automatically restarted after the crash.
  (CVE-2007-5925)
  
  All mysql users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "mysql on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2007-December/014524.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307827");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:31:09 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2007-5969", "CVE-2007-5925");
  script_name( "CentOS Update for mysql CESA-2007:1155 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of mysql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~4.1.20~3.RHEL4.1.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~4.1.20~3.RHEL4.1.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~4.1.20~3.RHEL4.1.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~4.1.20~3.RHEL4.1.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for e2fsprogs CESA-2008:0003 centos3 i386
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
tag_insight = "The e2fsprogs packages contain a number of utilities for creating,
  checking, modifying, and correcting any inconsistencies in second and third
  extended (ext2/ext3) file systems.

  Multiple integer overflow flaws were found in the way e2fsprogs processes
  file system content. If a victim opens a carefully crafted file system with
  a program using e2fsprogs, it may be possible to execute arbitrary code
  with the permissions of the victim. It may be possible to leverage this
  flaw in a virtualized environment to gain access to other virtualized
  hosts. (CVE-2007-5497)
  
  Red Hat would like to thank Rafal Wojtczuk of McAfee Avert Research for
  responsibly disclosing these issues.
  
  Users of e2fsprogs are advised to upgrade to these updated packages, which
  contain a backported patch to resolve these issues.";

tag_affected = "e2fsprogs on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-January/014565.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305912");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2007-5497");
  script_name( "CentOS Update for e2fsprogs CESA-2008:0003 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of e2fsprogs");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"e2fsprogs", rpm:"e2fsprogs~1.32~15.4", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"e2fsprogs-devel", rpm:"e2fsprogs-devel~1.32~15.4", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

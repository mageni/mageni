###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for tk CESA-2008:0135 centos4 i386
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
tag_insight = "Tk is a graphical toolkit for the Tcl scripting language.

  An input validation flaw was discovered in Tk's GIF image handling. A
  code-size value read from a GIF image was not properly validated before
  being used, leading to a buffer overflow. A specially crafted GIF file
  could use this to cause a crash or, potentially, execute code with the
  privileges of the application using the Tk graphical toolkit.
  (CVE-2008-0553)
  
  A buffer overflow flaw was discovered in Tk's animated GIF image handling.
  An animated GIF containing an initial image smaller than subsequent images
  could cause a crash or, potentially, execute code with the privileges of
  the application using the Tk library. (CVE-2007-5378)
  
  All users are advised to upgrade to these updated packages which contain a
  backported patches to resolve these issues.";

tag_affected = "tk on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-February/014699.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306349");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-0553", "CVE-2007-5378");
  script_name( "CentOS Update for tk CESA-2008:0135 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of tk");
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

  if ((res = isrpmvuln(pkg:"tk", rpm:"tk~8.4.7~3.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tk-devel", rpm:"tk-devel~8.4.7~3.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

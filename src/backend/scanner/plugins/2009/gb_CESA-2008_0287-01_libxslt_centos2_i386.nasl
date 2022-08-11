###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libxslt CESA-2008:0287-01 centos2 i386
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
tag_insight = "libxslt is a C library, based on libxml, for parsing of XML files into
  other textual formats (eg HTML, plain text and other XML representations of
  the underlying data). It uses the standard XSLT stylesheet transformation
  mechanism and, being written in plain ANSI C, is designed to be simple to
  incorporate into other applications

  Anthony de Almeida Lopes reported the libxslt library did not properly
  process long &quot;transformation match&quot; conditions in the XSL stylesheet files.
  An attacker could create a malicious XSL file that would cause a crash, or,
  possibly, execute and arbitrary code with the privileges of the application
  using libxslt library to perform XSL transformations. (CVE-2008-1767)
  
  All users are advised to upgrade to these updated packages, which contain a
  backported patch to resolve this issue.";

tag_affected = "libxslt on CentOS 2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-May/014926.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309736");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1767");
  script_name( "CentOS Update for libxslt CESA-2008:0287-01 centos2 i386");

  script_tag(name:"summary", value:"Check for the Version of libxslt");
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

if(release == "CentOS2")
{

  if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.0.15~3", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.0.15~3", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.0.15~3", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

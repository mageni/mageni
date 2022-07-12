###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gd CESA-2008:0146 centos4 i386
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
tag_insight = "The gd package contains a graphics library used for the dynamic creation of
  images such as PNG and JPEG.

  Multiple issues were discovered in the gd GIF image-handling code. A
  carefully-crafted GIF file could cause a crash or possibly execute code
  with the privileges of the application using the gd library.
  (CVE-2006-4484, CVE-2007-3475, CVE-2007-3476)
  
  An integer overflow was discovered in the gdImageCreateTrueColor()
  function, leading to incorrect memory allocations. A carefully crafted
  image could cause a crash or possibly execute code with the privileges of
  the application using the gd library. (CVE-2007-3472)
  
  A buffer over-read flaw was discovered. This could cause a crash in an
  application using the gd library to render certain strings using a
  JIS-encoded font. (CVE-2007-0455)
  
  A flaw was discovered in the gd PNG image handling code. A truncated PNG
  image could cause an infinite loop in an application using the gd library.
  (CVE-2007-2756)
  
  A flaw was discovered in the gd X BitMap (XBM) image-handling code. A
  malformed or truncated XBM image could cause a crash in an application
  using the gd library. (CVE-2007-3473)
  
  Users of gd should upgrade to these updated packages, which contain
  backported patches which resolve these issues.";

tag_affected = "gd on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-February/014732.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308984");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-4484", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3475", "CVE-2007-3476");
  script_name( "CentOS Update for gd CESA-2008:0146 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of gd");
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

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.28~5.4E.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-devel", rpm:"gd-devel~2.0.28~5.4E.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-progs", rpm:"gd-progs~2.0.28~5.4E.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

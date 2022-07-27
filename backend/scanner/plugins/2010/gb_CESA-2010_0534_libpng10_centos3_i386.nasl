###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libpng10 CESA-2010:0534 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A memory corruption flaw was found in the way applications, using the
  libpng library and its progressive reading method, decoded certain PNG
  images. An attacker could create a specially-crafted PNG image that, when
  opened, could cause an application using libpng to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2010-1205)

  A denial of service flaw was found in the way applications using the libpng
  library decoded PNG images that have certain, highly compressed ancillary
  chunks. An attacker could create a specially-crafted PNG image that could
  cause an application using libpng to consume excessive amounts of memory
  and CPU time, and possibly crash. (CVE-2010-0205)

  A memory leak flaw was found in the way applications using the libpng
  library decoded PNG images that use the Physical Scale (sCAL) extension. An
  attacker could create a specially-crafted PNG image that could cause an
  application using libpng to exhaust all available memory and possibly crash
  or exit. (CVE-2010-2249)

  A sensitive information disclosure flaw was found in the way applications
  using the libpng library processed 1-bit interlaced PNG images. An attacker
  could create a specially-crafted PNG image that could cause an application
  using libpng to disclose uninitialized memory. (CVE-2009-2042)

  Users of libpng and libpng10 should upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  applications using libpng or libpng10 must be restarted for the update to
  take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "libpng10 on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-August/016918.html");
  script_oid("1.3.6.1.4.1.25623.1.0.312862");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-20 14:57:11 +0200 (Fri, 20 Aug 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2042", "CVE-2010-0205", "CVE-2010-1205", "CVE-2010-2249");
  script_name("CentOS Update for libpng10 CESA-2010:0534 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of libpng10");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

  if ((res = isrpmvuln(pkg:"libpng10", rpm:"libpng10~1.0.13~21", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng10-devel", rpm:"libpng10-devel~1.0.13~21", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.2~30", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.2~30", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

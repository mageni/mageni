###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ImageMagick CESA-2008:0145 centos4 x86_64
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
tag_insight = "ImageMagick is an image display and manipulation tool for the X Window
  System that can read and write multiple image formats.

  Several heap-based buffer overflow flaws were found in ImageMagick. If a
  victim opened a specially crafted DCM or XWD file, an attacker could
  potentially execute arbitrary code on the victim's machine. (CVE-2007-1797)
  
  Several denial of service flaws were found in ImageMagick's parsing of XCF
  and DCM files. Attempting to process a specially-crafted input file in
  these formats could cause ImageMagick to enter an infinite loop.
  (CVE-2007-4985)
  
  Several integer overflow flaws were found in ImageMagick. If a victim
  opened a specially-crafted DCM, DIB, XBM, XCF or XWD file, an attacker
  could potentially execute arbitrary code with the privileges of the user
  running ImageMagick. (CVE-2007-4986)
  
  An integer overflow flaw was found in ImageMagick's DIB parsing code. If a
  victim opened a specially-crafted DIB file, an attacker could potentially
  execute arbitrary code with the privileges of the user running ImageMagick.
  (CVE-2007-4988)
  
  A heap-based buffer overflow flaw was found in the way ImageMagick parsed
  XCF files. If a specially-crafted XCF image was opened, ImageMagick could
  be made to overwrite heap memory beyond the bounds of its allocated memory.
  This could, potentially, allow an attacker to execute arbitrary code on the
  machine running ImageMagick. (CVE-2008-1096)
  
  A heap-based buffer overflow flaw was found in ImageMagick's processing of
  certain malformed PCX images. If a victim opened a specially-crafted PCX
  file, an attacker could possibly execute arbitrary code on the victim's
  machine. (CVE-2008-1097)
  
  All users of ImageMagick should upgrade to these updated packages, which
  contain backported patches to correct these issues.";

tag_affected = "ImageMagick on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-April/014840.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306649");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097");
  script_name( "CentOS Update for ImageMagick CESA-2008:0145 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of ImageMagick");
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

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.0.7.1~17.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.0.7.1~17.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++-devel", rpm:"ImageMagick-c++-devel~6.0.7.1~17.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.0.7.1~17.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.0.7.1~17.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

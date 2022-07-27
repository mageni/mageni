###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mjpegtools MDVA-2010:041 (mjpegtools)
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
tag_insight = "jpeg2yuv (from the mjpegtools package) segfaulted when linked against
  libjpeg v7/8 (#55450).

  The provided packages has been patched to address this issue.";

tag_affected = "mjpegtools on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-01/msg00075.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313324");
  script_version("$Revision: 8457 $");
  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-29 14:09:25 +0100 (Fri, 29 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "MDVA", value: "2010:041");
  script_name("Mandriva Update for mjpegtools MDVA-2010:041 (mjpegtools)");

  script_tag(name: "summary" , value: "Check for the Version of mjpegtools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"libmjpegtools1.9_0", rpm:"libmjpegtools1.9_0~1.9.0~3.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmjpegtools1.9_0-devel", rpm:"libmjpegtools1.9_0-devel~1.9.0~3.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mjpegtools", rpm:"mjpegtools~1.9.0~3.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mjpegtools1.9_0", rpm:"lib64mjpegtools1.9_0~1.9.0~3.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64mjpegtools1.9_0-devel", rpm:"lib64mjpegtools1.9_0-devel~1.9.0~3.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

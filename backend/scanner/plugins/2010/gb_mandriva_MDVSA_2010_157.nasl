###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for freetype2 MDVSA-2010:157 (freetype2)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in freetype2:

  The FT_Stream_EnterFrame function in base/ftstream.c in FreeType
  before 2.4.2 does not properly validate certain position values, which
  allows remote attackers to cause a denial of service (application
  crash) or possibly execute arbitrary code via a crafted font file
  (CVE-2010-2805).

  Array index error in the t42_parse_sfnts function in type42/t42parse.c
  in FreeType before 2.4.2 allows remote attackers to cause a denial of
  service (application crash) or possibly execute arbitrary code via
  negative size values for certain strings in FontType42 font files,
  leading to a heap-based buffer overflow (CVE-2010-2806).

  FreeType before 2.4.2 uses incorrect integer data types during bounds
  checking, which allows remote attackers to cause a denial of service
  (application crash) or possibly execute arbitrary code via a crafted
  font file (CVE-2010-2807).

  Buffer overflow in the Mac_Read_POST_Resource function in base/ftobjs.c
  in FreeType before 2.4.2 allows remote attackers to cause a denial of
  service (memory corruption and application crash) or possibly execute
  arbitrary code via a crafted Adobe Type 1 Mac Font File (aka LWFN)
  font (CVE-2010-2808).

  bdf/bdflib.c in FreeType before 2.4.2 allows remote attackers to cause
  a denial of service (application crash) via a crafted BDF font file,
  related to an attempted modification of a value in a static string
  (CVE-2010-3053).

  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "freetype2 on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-08/msg00017.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314145");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-24 07:04:19 +0200 (Tue, 24 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:157");
  script_cve_id("CVE-2010-2805", "CVE-2010-2806", "CVE-2010-2807", "CVE-2010-2808", "CVE-2010-3053");
  script_name("Mandriva Update for freetype2 MDVSA-2010:157 (freetype2)");

  script_tag(name: "summary" , value: "Check for the Version of freetype2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.3.11~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for libpng MDVSA-2010:063 (libpng)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in libpng:

  libpng before 1.2.37 does not properly parse 1-bit interlaced images
  with width values that are not divisible by 8, which causes libpng
  to include uninitialized bits in certain rows of a PNG file and
  might allow remote attackers to read portions of sensitive memory
  via out-of-bounds pixels in the file (CVE-2009-2042).
  
  The png_decompress_chunk function in pngrutil.c in libpng 1.0.x before
  1.0.53, 1.2.x before 1.2.43, and 1.4.x before 1.4.1 does not properly
  handle compressed ancillary-chunk data that has a disproportionately
  large uncompressed representation, which allows remote attackers to
  cause a denial of service (memory and CPU consumption, and application
  hang) via a crafted PNG file, as demonstrated by use of the deflate
  compression method on data composed of many occurrences of the same
  character, related to a decompression bomb attack (CVE-2010-0205).
  
  Packages for 2008.0 are provided for Corporate Desktop 2008.0
  customers.
  
  The updated packages have been patched to correct these issues.";

tag_affected = "libpng on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-03/msg00038.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314883");
  script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-31 14:20:46 +0200 (Wed, 31 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "MDVSA", value: "2010:063");
  script_cve_id("CVE-2009-2042", "CVE-2010-0205");
  script_name("Mandriva Update for libpng MDVSA-2010:063 (libpng)");

  script_tag(name: "summary" , value: "Check for the Version of libpng");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-source", rpm:"libpng-source~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-static-devel", rpm:"libpng-static-devel~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64png3", rpm:"lib64png3~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64png-static-devel", rpm:"lib64png-static-devel~1.2.22~0.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

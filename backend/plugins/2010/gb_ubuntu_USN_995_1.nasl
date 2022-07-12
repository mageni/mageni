###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_995_1.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# Ubuntu Update for libmikmod vulnerabilities USN-995-1
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
tag_insight = "It was discovered that libMikMod incorrectly handled songs with different
  channel counts. If a user were tricked into opening a crafted song file,
  an attacker could cause a denial of service. (CVE-2007-6720)

  It was discovered that libMikMod incorrectly handled certain malformed XM
  files. If a user were tricked into opening a crafted XM file, an attacker
  could cause a denial of service. (CVE-2009-0179)
  
  It was discovered that libMikMod incorrectly handled certain malformed
  Impulse Tracker files. If a user were tricked into opening a crafted
  Impulse Tracker file, an attacker could cause a denial of service or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2009-3995, CVE-2010-2546, CVE-2010-2971)
  
  It was discovered that libMikMod incorrectly handled certain malformed
  Ultratracker files. If a user were tricked into opening a crafted
  Ultratracker file, an attacker could cause a denial of service or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2009-3996)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-995-1";
tag_affected = "libmikmod vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-995-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.314985");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-01 16:10:21 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6720", "CVE-2009-0179", "CVE-2009-3995", "CVE-2009-3996", "CVE-2010-2546", "CVE-2010-2971");
  script_name("Ubuntu Update for libmikmod vulnerabilities USN-995-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"libmikmod2-dev", ver:"3.1.11-a-6ubuntu4.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmikmod2", ver:"3.1.11-a-6ubuntu4.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"libmikmod2-dev", ver:"3.1.11-a-6ubuntu3.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmikmod2", ver:"3.1.11-a-6ubuntu3.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmikmod2-dev", ver:"3.1.11-a-6ubuntu3.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmikmod2", ver:"3.1.11-a-6ubuntu3.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1004_1.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Ubuntu Update for python-django vulnerability USN-1004-1
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
tag_insight = "It was discovered that Django did not properly sanitize the cookie value
  when applying CSRF protections resulting in a cross-site scripting (XSS)
  vulnerability. With cross-site scripting vulnerabilities, if a user were
  tricked into viewing server output during a crafted server request, a
  remote attacker could exploit this to modify the contents, or steal
  confidential data, within the same domain.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1004-1";
tag_affected = "python-django vulnerability on Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1004-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.315044");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-23 15:30:07 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3082");
  script_name("Ubuntu Update for python-django vulnerability USN-1004-1");

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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-1ubuntu0.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-1ubuntu0.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

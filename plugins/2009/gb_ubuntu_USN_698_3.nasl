###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_698_3.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for nagios2 vulnerabilities USN-698-3
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
tag_insight = "It was discovered that Nagios was vulnerable to a Cross-site request forgery
  (CSRF) vulnerability. If an authenticated nagios user were tricked into
  clicking a link on a specially crafted web page, an attacker could trigger
  commands to be processed by Nagios and execute arbitrary programs. This
  update alters Nagios behaviour by disabling submission of CMD_CHANGE commands.
  (CVE-2008-5028)

  It was discovered that Nagios did not properly parse commands submitted using
  the web interface. An authenticated user could use a custom form or a browser
  addon to bypass security restrictions and submit unauthorized commands.
  (CVE-2008-5027)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-698-3";
tag_affected = "nagios2 vulnerabilities on Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-698-3/");
  script_oid("1.3.6.1.4.1.25623.1.0.310028");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5027", "CVE-2008-5028");
  script_name( "Ubuntu Update for nagios2 vulnerabilities USN-698-3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"nagios2-dbg", ver:"2.11-1ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nagios2", ver:"2.11-1ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nagios2-common", ver:"2.11-1ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nagios2-doc", ver:"2.11-1ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

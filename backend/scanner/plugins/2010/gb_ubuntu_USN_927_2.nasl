###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_927_2.nasl 8250 2017-12-27 07:29:15Z teissa $
#
# Ubuntu Update for nss regression USN-927-2
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
tag_insight = "USN-927-1 fixed vulnerabilities in NSS. Upstream NSS 3.12.6 added an
  additional checksum verification on libnssdbm3.so, but the Ubuntu packaging
  did not create this checksum. As a result, Firefox could not initialize the
  security component when the NSS Internal FIPS PKCS #11 Module was enabled.
  This update fixes the problem.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
  protocols. If an attacker could perform a man in the middle attack at the
  start of a TLS connection, the attacker could inject arbitrary content at
  the beginning of the user's session. This update adds support for the new
  new renegotiation extension and will use it when the server supports it.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-927-2";
tag_affected = "nss regression on Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-927-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.314696");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-16 17:02:11 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Ubuntu Update for nss regression USN-927-2");

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

  if ((res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.6-0ubuntu0.9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.6-0ubuntu0.9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.6-0ubuntu0.9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3-0d", ver:"3.12.6-0ubuntu0.9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.6-0ubuntu0.9.10.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_674_2.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for hplip vulnerabilities USN-674-2
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
tag_insight = "USN-674-1 provided packages to fix vulnerabilities in HPLIP. Due to an
  internal archive problem, the updates for Ubuntu 7.10 would not install
  properly. This update provides fixed packages for Ubuntu 7.10.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  It was discovered that the hpssd tool of hplip did not validate
  privileges in the alert-mailing function. A local attacker could
  exploit this to gain privileges and send e-mail messages from the
  account of the hplip user. This update alters hplip behaviour by
  preventing users from setting alerts and by moving alert configuration
  to a root-controlled /etc/hp/alerts.conf file. (CVE-2008-2940)
  
  It was discovered that the hpssd tool of hplip did not correctly
  handle certain commands. A local attacker could use a specially
  crafted packet to crash hpssd, leading to a denial of service.
  (CVE-2008-2941)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-674-2";
tag_affected = "hplip vulnerabilities on Ubuntu 7.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-674-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.306034");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2940", "CVE-2008-2941");
  script_name( "Ubuntu Update for hplip vulnerabilities USN-674-2");

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

if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"hpijs", ver:"2.7.7+2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"hplip-dbg", ver:"2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"hplip", ver:"2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"hplip-data", ver:"2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"hplip-doc", ver:"2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"hplip-gui", ver:"2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"hpijs-ppds", ver:"2.7.7+2.7.7.dfsg.1-0ubuntu5.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_612_7.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for openssh update USN-612-7
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
tag_insight = "USN-612-2 introduced protections for OpenSSH, related to the OpenSSL
  vulnerabilities addressed by USN-612-1.  This update provides the
  corresponding updates for OpenSSH in Ubuntu 6.06 LTS.  While the OpenSSL
  in Ubuntu 6.06 is not vulnerable, this update will block weak keys
  generated on systems that may have been affected themselves.

  Original advisory details:
  
  A weakness has been discovered in the random number generator used
  by OpenSSL on Debian and Ubuntu systems.  As a result of this
  weakness, certain encryption keys are much more common than they
  should be, such that an attacker could guess the key through a
  brute-force attack given minimal knowledge of the system.  This
  particularly affects the use of encryption keys in OpenSSH, OpenVPN
  and SSL certificates.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-612-7";
tag_affected = "openssh update on Ubuntu 6.06 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-612-7/");
  script_oid("1.3.6.1.4.1.25623.1.0.311739");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2008-0166");
  script_name( "Ubuntu Update for openssh update USN-612-7");

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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"openssh-client", ver:"4.2p1-7ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"4.2p1-7ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"4.2p1-7ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh", ver:"4.2p1-7ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

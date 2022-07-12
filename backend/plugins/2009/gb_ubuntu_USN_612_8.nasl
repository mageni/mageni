###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_612_8.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for openssl-blacklist update USN-612-8
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
tag_insight = "USN-612-3 addressed a weakness in OpenSSL certificate and key
  generation in OpenVPN by introducing openssl-blacklist to aid in
  detecting vulnerable private keys. This update enhances the
  openssl-vulnkey tool to check X.509 certificates as well, and
  provides the corresponding update for Ubuntu 6.06. While the
  OpenSSL in Ubuntu 6.06 was not vulnerable, openssl-blacklist is
  now provided for Ubuntu 6.06 for checking certificates and keys
  that may have been imported on these systems.

  This update also includes the complete RSA-1024 and RSA-2048
  blacklists for all Ubuntu architectures, as well as support for
  other future blacklists for non-standard bit lengths.
  
  You can check for weak SSL/TLS certificates by installing
  openssl-blacklist via your package manager, and using the
  openssl-vulnkey command.
  
  $ openssl-vulnkey /path/to/certificate_or_key
  
  This command can be used on public certificates and private keys
  for any X.509 certificate or RSA key, including ones for web
  servers, mail servers, OpenVPN, and others. If in doubt, destroy
  the certificate and key and generate new ones. Please consult the
  documentation for your software when recreating SSL/TLS
  certificates. Also, if certificates have been generated for use
  on other systems, they must be found and replaced as well.
  
  Original advisory details:
  
  A weakness has been discovered in the random number generator used
  by OpenSSL on Debian and Ubuntu systems.  As a result of this
  weakness, certain encryption keys are much more common than they
  should be, such that an attacker could guess the key through a
  brute-force attack given minimal knowledge of the system.  This
  particularly affects the use of encryption keys in OpenSSH, OpenVPN
  and SSL certificates.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-612-8";
tag_affected = "openssl-blacklist update on Ubuntu 6.06 LTS ,
  Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-612-8/");
  script_oid("1.3.6.1.4.1.25623.1.0.305214");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name( "Ubuntu Update for openssl-blacklist update USN-612-8");

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

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.1-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.1-0ubuntu0.7.04.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.1-0ubuntu0.8.04.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.1-0ubuntu0.7.10.4", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

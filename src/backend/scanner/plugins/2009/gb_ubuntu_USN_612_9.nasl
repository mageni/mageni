###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_612_9.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for openssl-blacklist update USN-612-9
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
  openssl-vulnkey tool to check Certificate Signing Requests, accept
  input from STDIN, and check moduli without a certificate.

  It was also discovered that additional moduli are vulnerable if
  generated with OpenSSL 0.9.8g or higher. While it is believed that
  there are few of these vulnerable moduli in use, this update
  includes updated RSA-1024 and RSA-2048 blacklists. RSA-512
  blacklists are also included in the new openssl-blacklist-extra
  package.
  
  You can check for weak SSL/TLS certificates by installing
  openssl-blacklist via your package manager, and using the
  openssl-vulnkey command.
  
  $ openssl-vulnkey /path/to/certificate_or_key
  then pipe it to 'openvas-vulnkey - '
  
  You can also check if a modulus is vulnerable by specifying the
  modulus and number of bits.
  
  $ openssl-vulnkey -b bits -m modulus
  
  These commands can be used on public certificates, requests, and
  private keys for any X.509 certificate, CSR, or RSA key, including
  ones for web servers, mail servers, OpenVPN, and others. If in
  doubt, destroy the certificate and key and generate new ones.
  Please consult the documentation for your software when recreating
  SSL/TLS certificates. Also, if certificates have been generated
  for use on other systems, they must be found and replaced as well.
  
  Original advisory details:
  A weakness has been discovered in the random number generator used
  by OpenSSL on Debian and Ubuntu systems. As a result of this
  weakness, certain encryption keys are much more common than they
  should be, such that an attacker could guess the key through a
  brute-force attack given minimal knowledge of the system. This
  particularly affects the use of encryption keys in OpenSSH, OpenVPN
  and SSL certificates.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-612-9";
tag_affected = "openssl-blacklist update on Ubuntu 6.06 LTS ,
  Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-612-9/");
  script_oid("1.3.6.1.4.1.25623.1.0.305865");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name( "Ubuntu Update for openssl-blacklist update USN-612-9");

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

  if ((res = isdpkgvuln(pkg:"openssl-blacklist-extra", ver:"0.3.3+0.4-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.3.3+0.4-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"openssl-blacklist-extra", ver:"0.3.3+0.4-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.3.3+0.4-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openssl-blacklist-extra", ver:"0.3.3+0.4-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.3.3+0.4-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"openssl-blacklist-extra", ver:"0.3.3+0.4-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-blacklist", ver:"0.3.3+0.4-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

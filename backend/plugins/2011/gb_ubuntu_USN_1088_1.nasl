###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1088_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for krb5 vulnerability USN-1088-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1088-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840616");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-24 14:29:52 +0100 (Thu, 24 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0284");
  script_name("Ubuntu Update for krb5 vulnerability USN-1088-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(9\.10|10\.10|10\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1088-1");
  script_tag(name:"affected", value:"krb5 vulnerability on Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Cameron Meadors discovered that the MIT Kerberos 5 Key Distribution
  Center (KDC) daemon is vulnerable to a double-free condition if
  the Public Key Cryptography for Initial Authentication (PKINIT)
  capability is enabled. This could allow a remote attacker to cause
  a denial of service.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm5clnt6", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm5srv6", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkdb5-4", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.7dfsg~beta3-1ubuntu0.12", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm5clnt-mit7", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm5srv-mit7", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkdb5-4", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.8.1+dfsg-5ubuntu0.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm5clnt-mit7", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm5srv-mit7", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkdb5-4", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.8.1+dfsg-2ubuntu0.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

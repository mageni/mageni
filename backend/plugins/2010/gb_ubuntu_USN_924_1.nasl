###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_924_1.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Ubuntu Update for krb5 vulnerabilities USN-924-1
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
tag_insight = "Sol Jerome discovered that the Kerberos kadmind service did not correctly
  free memory.  An unauthenticated remote attacker could send specially
  crafted traffic to crash the kadmind process, leading to a denial of
  service. (CVE-2010-0629)

  It was discovered that Kerberos did not correctly free memory in
  the GSSAPI library.  If a remote attacker were able to manipulate an
  application using GSSAPI carefully, the service could crash, leading to
  a denial of service.  (Ubuntu 8.10 was not affected.)  (CVE-2007-5901,
  CVE-2007-5971)
  
  It was discovered that Kerberos did not correctly free memory in the
  GSSAPI and kdb libraries.  If a remote attacker were able to manipulate
  an application using these libraries carefully, the service could crash,
  leading to a denial of service.  (Only Ubuntu 8.04 LTS was affected.)
  (CVE-2007-5902, CVE-2007-5972)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-924-1";
tag_affected = "krb5 vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 8.10 ,
  Ubuntu 9.04";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-924-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.313866");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-09 11:11:25 +0200 (Fri, 09 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-5901", "CVE-2007-5902", "CVE-2007-5971", "CVE-2007-5972", "CVE-2010-0629");
  script_name("Ubuntu Update for krb5 vulnerabilities USN-924-1");

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

if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

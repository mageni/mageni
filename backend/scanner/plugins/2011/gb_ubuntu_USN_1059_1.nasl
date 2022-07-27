###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1059_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for dovecot vulnerabilities USN-1059-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1059-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840583");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707", "CVE-2010-3779", "CVE-2010-3780");
  script_name("Ubuntu Update for dovecot vulnerabilities USN-1059-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1059-1");
  script_tag(name:"affected", value:"dovecot vulnerabilities on Ubuntu 10.04 LTS,
  Ubuntu 10.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the ACL plugin in Dovecot would incorrectly
  propagate ACLs to new mailboxes. A remote authenticated user could possibly
  read new mailboxes that were created with the wrong ACL. (CVE-2010-3304)

  It was discovered that the ACL plugin in Dovecot would incorrectly merge
  ACLs in certain circumstances. A remote authenticated user could possibly
  bypass intended access restrictions and gain access to mailboxes.
  (CVE-2010-3706, CVE-2010-3707)

  It was discovered that the ACL plugin in Dovecot would incorrectly grant
  the admin permission to owners of certain mailboxes. A remote authenticated
  user could possibly bypass intended access restrictions and gain access to
  mailboxes. (CVE-2010-3779)

  It was discovered that Dovecot incorrecly handled the simultaneous
  disconnect of a large number of sessions. A remote authenticated user could
  use this flaw to cause Dovecot to crash, resulting in a denial of service.
  (CVE-2010-3780)");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"dovecot-common", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-postfix", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mail-stack-delivery", ver:"1.2.12-1ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"dovecot-common", ver:"1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"dovecot-postfix", ver:"1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_886_1.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Ubuntu Update for pidgin vulnerabilities USN-886-1
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
tag_insight = "It was discovered that Pidgin did not properly handle certain topic
  messages in the IRC protocol handler. If a user were tricked into
  connecting to a malicious IRC server, an attacker could cause Pidgin to
  crash, leading to a denial of service. This issue only affected Ubuntu 8.04
  LTS, Ubuntu 8.10 and Ubuntu 9.04. (CVE-2009-2703)

  It was discovered that Pidgin did not properly enforce the &quot;require
  TLS/SSL&quot; setting when connecting to certain older Jabber servers. If a
  remote attacker were able to perform a man-in-the-middle attack, this flaw
  could be exploited to view sensitive information. This issue only affected
  Ubuntu 8.04 LTS, Ubuntu 8.10 and Ubuntu 9.04. (CVE-2009-3026)
  
  It was discovered that Pidgin did not properly handle certain SLP invite
  messages in the MSN protocol handler. A remote attacker could send a
  specially crafted invite message and cause Pidgin to crash, leading to a
  denial of service. This issue only affected Ubuntu 8.04 LTS, Ubuntu 8.10
  and Ubuntu 9.04. (CVE-2009-3083)
  
  It was discovered that Pidgin did not properly handle certain errors in the
  XMPP protocol handler. A remote attacker could send a specially crafted
  message and cause Pidgin to crash, leading to a denial of service. This
  issue only affected Ubuntu 8.10 and Ubuntu 9.04. (CVE-2009-3085)
  
  It was discovered that Pidgin did not properly handle malformed
  contact-list data in the OSCAR protocol handler. A remote attacker could
  send specially crafted contact-list data and cause Pidgin to crash, leading
  to a denial of service. (CVE-2009-3615)
  
  It was discovered that Pidgin did not properly handle custom smiley
  requests in the MSN protocol handler. A remote attacker could send a
  specially crafted filename in a custom smiley request and obtain arbitrary
  files via directory traversal. This issue only affected Ubuntu 8.10, Ubuntu
  9.04 and Ubuntu 9.10. (CVE-2010-0013)
  
  Pidgin for Ubuntu 8.04 LTS was also updated to fix connection issues with
  the MSN protocol.
  
  USN-675-1 and USN-781-1 provided updated Pidgin packages to fix multiple
  security vulnerabilities in Ubuntu 8.04 LTS. The security patches to fix
  CVE-2008-2955 and CVE-2009-1376 were incomplete. This update corrects the
  problem. Original advisory details:
  
  It was discovered that Pidgin did not properly handle file transfers
  containing a long filename and special characters in the MSN protocol
  handler. A remote attacker could send a specially crafted filename in a
  file transfer request and cause Pidgin ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-886-1";
tag_affected = "pidgin vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 8.10 ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-886-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.313061");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-20 09:25:19 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2955", "CVE-2009-1376", "CVE-2009-2703", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3085", "CVE-2009-3615", "CVE-2010-0013");
  script_name("Ubuntu Update for pidgin vulnerabilities USN-886-1");

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

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.5.5-1ubuntu8.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.5.2-0ubuntu1.6", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"gaim", ver:"2.4.1-1ubuntu2.8", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.6.2-1ubuntu7.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

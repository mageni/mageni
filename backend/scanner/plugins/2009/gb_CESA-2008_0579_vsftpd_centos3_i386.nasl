###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for vsftpd CESA-2008:0579 centos3 i386
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
tag_insight = "vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure FTP
  server for Linux and Unix-like systems.

  The version of vsftpd as shipped in Red Hat Enterprise Linux 3 when used in
  combination with Pluggable Authentication Modules (PAM) had a memory leak
  on an invalid authentication attempt. Since vsftpd prior to version 2.0.5
  allows any number of invalid attempts on the same connection this memory
  leak could lead to an eventual DoS. (CVE-2008-2375)
  
  This update mitigates this security issue by including a backported patch
  which terminates a session after a given number of failed log in attempts.
  The default number of attempts is 3 and this can be configured using the
  &quot;max_login_fails&quot; directive.
  
  All vsftpd users should upgrade to this updated package, which addresses
  this vulnerability.";

tag_affected = "vsftpd on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-July/015165.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307161");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-2375");
  script_name( "CentOS Update for vsftpd CESA-2008:0579 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of vsftpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~1.2.1~3E.16", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

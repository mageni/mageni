###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2008:0005 centos3 x86_64
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
tag_insight = "The Apache HTTP Server is a popular Web server.

  A flaw was found in the mod_imap module. On sites where mod_imap was
  enabled and an imagemap file was publicly available, a cross-site scripting
  attack was possible. (CVE-2007-5000)
  
  A flaw was found in the mod_autoindex module. On sites where directory
  listings are used, and the &quot;AddDefaultCharset&quot; directive has been removed
  from the configuration, a cross-site scripting attack was possible against
  Web browsers which did not correctly derive the response character set
  following the rules in RFC 2616. (CVE-2007-4465)
  
  A flaw was found in the mod_proxy module. On sites where a reverse proxy is
  configured, a remote attacker could send a carefully crafted request that
  would cause the Apache child process handling that request to crash. On
  sites where a forward proxy is configured, an attacker could cause a
  similar crash if a user could be persuaded to visit a malicious site using
  the proxy. This could lead to a denial of service if using a threaded
  Multi-Processing Module. (CVE-2007-3847) 
  
  A flaw was found in the mod_status module. On sites where mod_status was
  enabled and the status pages were publicly available, a cross-site
  scripting attack was possible. (CVE-2007-6388)
  
  A flaw was found in the mod_proxy_ftp module. On sites where mod_proxy_ftp
  was enabled and a forward proxy was configured, a cross-site scripting
  attack was possible against Web browsers which did not correctly derive the
  response character set following the rules in RFC 2616. (CVE-2008-0005)
  
  Users of Apache httpd should upgrade to these updated packages, which
  contain backported patches to resolve these issues. Users should restart
  httpd after installing this update.";

tag_affected = "httpd on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-January/014606.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308946");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2008-0005");
  script_name( "CentOS Update for httpd CESA-2008:0005 centos3 x86_64");

  script_tag(name:"summary", value:"Check for the Version of httpd");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.46~70.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.46~70.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.46~70.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

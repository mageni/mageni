###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2008:0006-01
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
  Web browsers which do not correctly derive the response character set
  following the rules in RFC 2616. (CVE-2007-4465)
  
  A flaw was found in the mod_status module. On sites where mod_status was
  enabled and the status pages were publicly available, a cross-site
  scripting attack was possible. (CVE-2007-6388)
  
  A flaw was found in the mod_proxy_ftp module. On sites where mod_proxy_ftp
  was enabled and a forward proxy was configured, a cross-site scripting
  attack was possible against Web browsers which do not correctly derive the
  response character set following the rules in RFC 2616. (CVE-2008-0005)
  
  Users of Apache httpd should upgrade to these updated packages, which
  contain backported patches to resolve these issues. Users should restart
  httpd after installing this update.";

tag_affected = "httpd on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-January/msg00007.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305466");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "RHSA", value: "2008:0006-01");
  script_cve_id("CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2008-0005");
  script_name( "RedHat Update for httpd RHSA-2008:0006-01");

  script_tag(name:"summary", value:"Check for the Version of httpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.52~38.ent.2", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.0.52~38.ent.2", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.52~38.ent.2", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.0.52~38.ent.2", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-suexec", rpm:"httpd-suexec~2.0.52~38.ent.2", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.52~38.ent.2", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

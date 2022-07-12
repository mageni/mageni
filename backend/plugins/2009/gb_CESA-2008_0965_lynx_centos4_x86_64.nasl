###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for lynx CESA-2008:0965 centos4 x86_64
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
tag_insight = "Lynx is a text-based Web browser.

  An arbitrary command execution flaw was found in the Lynx &quot;lynxcgi:&quot; URI
  handler. An attacker could create a web page redirecting to a malicious URL
  that could execute arbitrary code as the user running Lynx in the
  non-default &quot;Advanced&quot; user mode. (CVE-2008-4690)
  
  Note: In these updated lynx packages, Lynx will always prompt users before
  loading a &quot;lynxcgi:&quot; URI. Additionally, the default lynx.cfg configuration
  file now marks all &quot;lynxcgi:&quot; URIs as untrusted by default.
  
  A flaw was found in a way Lynx handled &quot;.mailcap&quot; and &quot;.mime.types&quot;
  configuration files. Files in the browser's current working directory were
  opened before those in the user's home directory. A local attacker, able to
  convince a user to run Lynx in a directory under their control, could
  possibly execute arbitrary commands as the user running Lynx. (CVE-2006-7234)
  
  All users of Lynx are advised to upgrade to this updated package, which
  contains backported patches correcting these issues.";

tag_affected = "lynx on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-October/015358.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305771");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4690", "CVE-2006-7234");
  script_name( "CentOS Update for lynx CESA-2008:0965 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of lynx");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.5~18.2.el4_7.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for lynx RHSA-2008:0965-01
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

tag_affected = "lynx on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1,
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3,
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4,
  Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-October/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.312004");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0965-01");
  script_cve_id("CVE-2008-4690", "CVE-2006-7234");
  script_name( "RedHat Update for lynx RHSA-2008:0965-01");

  script_tag(name:"summary", value:"Check for the Version of lynx");
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

if(release == "RHENT_2.1")
{

  if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.4~18.1.3", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.5~28.1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lynx-debuginfo", rpm:"lynx-debuginfo~2.8.5~28.1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.5~18.2.el4_7.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lynx-debuginfo", rpm:"lynx-debuginfo~2.8.5~18.2.el4_7.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.5~11.3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lynx-debuginfo", rpm:"lynx-debuginfo~2.8.5~11.3", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pcsc-lite RHSA-2010:0533-01
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
tag_insight = "PC/SC Lite provides a Windows SCard compatible interface for communicating
  with smart cards, smart card readers, and other security tokens.

  Multiple buffer overflow flaws were discovered in the way the pcscd daemon,
  a resource manager that coordinates communications with smart card readers
  and smart cards connected to the system, handled client requests. A local
  user could create a specially-crafted request that would cause the pcscd
  daemon to crash or, possibly, execute arbitrary code. (CVE-2010-0407,
  CVE-2009-4901)
  
  Users of pcsc-lite should upgrade to these updated packages, which contain
  a backported patch to correct these issues. After installing this update,
  the pcscd daemon will be restarted automatically.";

tag_affected = "pcsc-lite on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-July/msg00007.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314398");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-16 10:40:49 +0200 (Fri, 16 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0533-01");
  script_cve_id("CVE-2009-4901", "CVE-2010-0407", "CVE-2009-4902");
  script_name("RedHat Update for pcsc-lite RHSA-2010:0533-01");

  script_tag(name: "summary" , value: "Check for the Version of pcsc-lite");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.4.4~4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-debuginfo", rpm:"pcsc-lite-debuginfo~1.4.4~4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-devel", rpm:"pcsc-lite-devel~1.4.4~4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-doc", rpm:"pcsc-lite-doc~1.4.4~4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite-libs", rpm:"pcsc-lite-libs~1.4.4~4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

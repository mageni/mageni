###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for systemtap RHSA-2010:0895-01
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
tag_insight = "SystemTap is an instrumentation system for systems running the Linux
  kernel, version 2.6. Developers can write scripts to collect data on the
  operation of the system. staprun, the SystemTap runtime tool, is used for
  managing SystemTap kernel modules (for example, loading them).

  It was discovered that staprun did not properly sanitize the environment
  before executing the modprobe command to load an additional kernel module.
  A local, unprivileged user could use this flaw to escalate their
  privileges. (CVE-2010-4170)
  
  Note: On Red Hat Enterprise Linux 4, an attacker must be a member of the
  stapusr group to exploit this issue. Also note that, after installing this
  update, users already in the stapdev group must be added to the stapusr
  group in order to be able to run the staprun tool.
  
  Red Hat would like to thank Tavis Ormandy for reporting this issue.
  
  SystemTap users should upgrade to these updated packages, which contain
  a backported patch to correct this issue.";

tag_affected = "systemtap on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-November/msg00030.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314706");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-23 15:30:07 +0100 (Tue, 23 Nov 2010)");
  script_xref(name: "RHSA", value: "2010:0895-01");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4170");
  script_name("RedHat Update for systemtap RHSA-2010:0895-01");

  script_tag(name: "summary" , value: "Check for the Version of systemtap");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~0.6.2~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-debuginfo", rpm:"systemtap-debuginfo~0.6.2~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~0.6.2~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-testsuite", rpm:"systemtap-testsuite~0.6.2~2.el4_8.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

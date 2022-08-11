###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pam RHSA-2010:0819-01
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
tag_insight = "Pluggable Authentication Modules (PAM) provide a system whereby
  administrators can set up authentication policies without having to
  recompile programs that handle authentication.

  It was discovered that the pam_namespace module executed the external
  script namespace.init with an unchanged environment inherited from an
  application calling PAM. In cases where such an environment was untrusted
  (for example, when pam_namespace was configured for setuid applications
  such as su or sudo), a local, unprivileged user could possibly use this
  flaw to escalate their privileges. (CVE-2010-3853)
  
  It was discovered that the pam_mail module used root privileges while
  accessing users' files. In certain configurations, a local, unprivileged
  user could use this flaw to obtain limited information about files or
  directories that they do not have access to. (CVE-2010-3435)
  
  It was discovered that the pam_xauth module did not verify the return
  values of the setuid() and setgid() system calls. A local, unprivileged
  user could use this flaw to execute the xauth command with root privileges
  and make it read an arbitrary input file. (CVE-2010-3316)
  
  Red Hat would like to thank Sebastian Krahmer of the SuSE Security Team for
  reporting the CVE-2010-3435 issue.
  
  All pam users should upgrade to these updated packages, which contain
  backported patches to correct these issues.";

tag_affected = "pam on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-November/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314005");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0819-01");
  script_cve_id("CVE-2010-3316", "CVE-2010-3435", "CVE-2010-3853");
  script_name("RedHat Update for pam RHSA-2010:0819-01");

  script_tag(name: "summary" , value: "Check for the Version of pam");
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

  if ((res = isrpmvuln(pkg:"pam", rpm:"pam~0.99.6.2~6.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~0.99.6.2~6.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~0.99.6.2~6.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

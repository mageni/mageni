###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for rpm RHSA-2010:0679-01
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
tag_insight = "The RPM Package Manager (RPM) is a command line driven package management
  system capable of installing, uninstalling, verifying, querying, and
  updating software packages.

  It was discovered that RPM did not remove setuid and setgid bits set on
  binaries when upgrading packages. A local attacker able to create hard
  links to binaries could use this flaw to keep those binaries on the system,
  at a specific version level and with the setuid or setgid bit set, even if
  the package providing them was upgraded by a system administrator. This
  could have security implications if a package was upgraded because of a
  security flaw in a setuid or setgid program. (CVE-2010-2059)

  This update also fixes the following bug:

  * A memory leak in the communication between RPM and the Security-Enhanced
  Linux (SELinux) subsystem, which could have caused extensive memory
  consumption. In reported cases, this issue was triggered by running
  rhn_check when errata were scheduled to be applied. (BZ#627630)

  All users of rpm are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.";

tag_affected = "rpm on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-September/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314167");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-10 14:21:00 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0679-01");
  script_cve_id("CVE-2010-2059");
  script_name("RedHat Update for rpm RHSA-2010:0679-01");

  script_tag(name: "summary" , value: "Check for the Version of rpm");
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

  if ((res = isrpmvuln(pkg:"popt", rpm:"popt~1.10.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-apidocs", rpm:"rpm-apidocs~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-debuginfo", rpm:"rpm-debuginfo~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-libs", rpm:"rpm-libs~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.4.2.3~20.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

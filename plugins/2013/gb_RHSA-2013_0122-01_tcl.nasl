###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tcl RHSA-2013:0122-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870875");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:41:33 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2007-4772", "CVE-2007-6067");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_name("RedHat Update for tcl RHSA-2013:0122-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"tcl on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Tcl (Tool Command Language) provides a powerful platform for creating
  integration applications that tie together diverse applications, protocols,
  devices, and frameworks. When paired with the Tk toolkit, Tcl provides a
  fast and powerful way to create cross-platform GUI applications.

  Two denial of service flaws were found in the Tcl regular expression
  handling engine. If Tcl or an application using Tcl processed a
  specially-crafted regular expression, it would lead to excessive CPU and
  memory consumption. (CVE-2007-4772, CVE-2007-6067)

  This update also fixes the following bug:

  * Due to a suboptimal implementation of threading in the current version of
  the Tcl language interpreter, an attempt to use threads in combination with
  fork in a Tcl script could cause the script to stop responding. At the
  moment, it is not possible to rewrite the source code or drop support for
  threading entirely. Consequent to this, this update provides a version of
  Tcl without threading support in addition to the standard version with this
  support. Users who need to use fork in their Tcl scripts and do not require
  threading can now switch to the version without threading support by using
  the alternatives command. (BZ#478961)

  All users of Tcl are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"tcl", rpm:"tcl~8.4.13~6.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl-debuginfo", rpm:"tcl-debuginfo~8.4.13~6.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl-devel", rpm:"tcl-devel~8.4.13~6.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl-html", rpm:"tcl-html~8.4.13~6.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

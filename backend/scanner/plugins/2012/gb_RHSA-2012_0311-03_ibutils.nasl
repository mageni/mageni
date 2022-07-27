###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ibutils RHSA-2012:0311-03
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00045.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870565");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:57:32 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2008-3277");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for ibutils RHSA-2012:0311-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ibutils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"ibutils on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The ibutils packages provide InfiniBand network and path diagnostics.

  It was found that the ibmssh executable had an insecure relative RPATH
  (runtime library search path) set in the ELF (Executable and Linking
  Format) header. A local user able to convince another user to run ibmssh in
  an attacker-controlled directory could run arbitrary code with the
  privileges of the victim. (CVE-2008-3277)

  This update also fixes the following bug:

  * Under certain circumstances, the 'ibdiagnet -r' command could suffer from
  memory corruption and terminate with a 'double free or corruption' message
  and a backtrace. With this update, the correct memory management function
  is used to prevent the corruption. (BZ#711779)

  All users of ibutils are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-debuginfo", rpm:"ibutils-debuginfo~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-devel", rpm:"ibutils-devel~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.2~11.2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

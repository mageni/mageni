###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for system-config-firewall RHSA-2011:0953-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870650");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:41:27 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-2520");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_name("RedHat Update for system-config-firewall RHSA-2011:0953-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'system-config-firewall'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"system-config-firewall on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"system-config-firewall is a graphical user interface for basic firewall
  setup.

  It was found that system-config-firewall used the Python pickle module in
  an insecure way when sending data (via D-Bus) to the privileged back-end
  mechanism. A local user authorized to configure firewall rules using
  system-config-firewall could use this flaw to execute arbitrary code with
  root privileges, by sending a specially-crafted serialized object.
  (CVE-2011-2520)

  Red Hat would like to thank Marco Slaviero of SensePost for reporting this
  issue.

  This erratum updates system-config-firewall to use JSON (JavaScript Object
  Notation) for data exchange, instead of pickle. Therefore, an updated
  version of system-config-printer that uses this new communication data
  format is also provided in this erratum.

  Users of system-config-firewall are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. Running
  instances of system-config-firewall must be restarted before the utility
  will be able to communicate with its updated back-end.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"system-config-printer", rpm:"system-config-printer~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-debuginfo", rpm:"system-config-printer-debuginfo~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-libs", rpm:"system-config-printer-libs~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-udev", rpm:"system-config-printer-udev~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-firewall", rpm:"system-config-firewall~1.2.27~3.el6_1.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-firewall-base", rpm:"system-config-firewall-base~1.2.27~3.el6_1.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-firewall-tui", rpm:"system-config-firewall-tui~1.2.27~3.el6_1.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

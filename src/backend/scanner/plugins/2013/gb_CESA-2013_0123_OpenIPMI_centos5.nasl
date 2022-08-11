###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for OpenIPMI CESA-2013:0123 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019151.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881560");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:38:06 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2011-4339");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_name("CentOS Update for OpenIPMI CESA-2013:0123 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenIPMI'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"OpenIPMI on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The OpenIPMI packages provide command line tools and utilities to access
  platform information using Intelligent Platform Management Interface
  (IPMI). System administrators can use OpenIPMI to manage systems and to
  perform system health monitoring.

  It was discovered that the IPMI event daemon (ipmievd) created its process
  ID (PID) file with world-writable permissions. A local user could use this
  flaw to make the ipmievd init script kill an arbitrary process when the
  ipmievd daemon is stopped or restarted. (CVE-2011-4339)

  Note: This issue did not affect the default configuration of OpenIPMI as
  shipped with Red Hat Enterprise Linux 5.

  This update also fixes the following bugs:

  * Prior to this update, the ipmitool utility first checked the IPMI
  hardware for Dell IPMI extensions and listed only supported commands when
  printing command usage like the option 'ipmtool delloem help'. On a
  non-Dell platform, the usage text was incomplete and misleading. This
  update lists all Dell OEM extensions in usage texts on all platforms, which
  allows users to check for command line arguments on non-Dell hardware.
  (BZ#658762)

  * Prior to this update, the ipmitool utility tried to retrieve the Sensor
  Data Records (SDR) from the IPMI bus instead of the Baseboard Management
  Controller (BMC) bus when IPMI-enabled devices reported SDR under a
  different owner than the BMC. As a consequence, the timeout setting for the
  SDR read attempt could significantly decrease the performance and no sensor
  data was shown. This update modifies ipmitool to read these SDR records
  from the BMC and shows the correct sensor data on these platforms.
  (BZ#671059, BZ#749796)

  * Prior to this update, the exit code of the 'ipmitool -o list' option was
  not set correctly. As a consequence, 'ipmitool -o list' always returned the
  value 1 instead of the expected value 0. This update modifies the
  underlying code to return the value 0 as expected. (BZ#740780)

  * Prior to this update, the 'ipmi' service init script did not specify the
  full path to the '/sbin/lsmod' and '/sbin/modprobe' system utilities. As a
  consequence, the init script failed when it was executed if PATH did not
  point to /sbin, for example, when running 'sudo /etc/init.d/ipmi'. This
  update modifies the init script so that it now contains the full path to
  lsmod and modrpobe. Now, it can be executed with sudo. (BZ#829705)

  * Prior to this update, the ipmitool man page did not list the '-b', '-B',
  '-l' ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"OpenIPMI", rpm:"OpenIPMI~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenIPMI-devel", rpm:"OpenIPMI-devel~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenIPMI-gui", rpm:"OpenIPMI-gui~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenIPMI-libs", rpm:"OpenIPMI-libs~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenIPMI-perl", rpm:"OpenIPMI-perl~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenIPMI-python", rpm:"OpenIPMI-python~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenIPMI-tools", rpm:"OpenIPMI-tools~2.0.16~16.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for net-snmp RHSA-2015:1385-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871407");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2014-3565");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:26:21 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for net-snmp RHSA-2015:1385-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The net-snmp packages provide various libraries and tools for the Simple
Network Management Protocol (SNMP), including an SNMP library, an
extensible agent, tools for requesting or setting information from SNMP
agents, tools for generating and handling SNMP traps, a version of the
netstat command which uses SNMP, and a Tk/Perl Management Information Base
(MIB) browser.

A denial of service flaw was found in the way snmptrapd handled certain
SNMP traps when started with the '-OQ' option. If an attacker sent an SNMP
trap containing a variable with a NULL type where an integer variable type
was expected, it would cause snmptrapd to crash. (CVE-2014-3565)

This update also fixes the following bugs:

  * The HOST-RESOURCES-MIB::hrSystemProcesses object was not implemented
because parts of the HOST-RESOURCES-MIB module were rewritten in an earlier
version of net-snmp. Consequently, HOST-RESOURCES-MIB::hrSystemProcesses
did not provide information on the number of currently loaded or running
processes. With this update, HOST-RESOURCES-MIB::hrSystemProcesses has been
implemented, and the net-snmp daemon reports as expected. (BZ#1134335)

  * The Net-SNMP agent daemon, snmpd, reloaded the system ARP table every 60
seconds. As a consequence, snmpd could cause a short CPU usage spike on
busy systems with a large APR table. With this update, snmpd does not
reload the full ARP table periodically, but monitors the table changes
using a netlink socket. (BZ#789500)

  * Previously, snmpd used an invalid pointer to the current time when
periodically checking certain conditions specified by the 'monitor' option
in the /etc/snmpd/snmpd.conf file. Consequently, snmpd terminated
unexpectedly on start with a segmentation fault if a certain entry with the
'monitor' option was used. Now, snmpd initializes the correct pointer
to the current time, and snmpd no longer crashes on start. (BZ#1050970)

  * Previously, snmpd expected 8-bit network interface indices when
processing HOST-RESOURCES-MIB::hrDeviceTable. If an interface index of a
local network interface was larger than 30, 000 items, snmpd could terminate
unexpectedly due to accessing invalid memory. Now, processing of all
network sizes is enabled, and snmpd no longer crashes in the described
situation. (BZ#1195547)

  * The snmpdtrapd service incorrectly checked for errors when forwarding a
trap with a RequestID value of 0, and logged 'Forward failed' even though
the trap was successfully forwarded. This update fixes snmptrapd checks and
the aforementioned ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"net-snmp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00027.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.5~54.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

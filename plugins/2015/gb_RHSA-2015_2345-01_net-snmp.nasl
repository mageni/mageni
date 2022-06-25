###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for net-snmp RHSA-2015:2345-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871490");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:21:31 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-3565");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for net-snmp RHSA-2015:2345-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The net-snmp packages provide various
libraries and tools for the Simple Network Management Protocol (SNMP), including
an SNMP library, an extensible agent, tools for requesting or setting
information from SNMP agents, tools for generating and handling SNMP traps, a
version of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A denial of service flaw was found in the way snmptrapd handled certain
SNMP traps when started with the '-OQ' option. If an attacker sent an SNMP
trap containing a variable with a NULL type where an integer variable type
was expected, it would cause snmptrapd to crash. (CVE-2014-3565)

This update also fixes the following bugs:

  * Previously, the clientaddr option in the snmp.conf file affected outgoing
messages sent only over IPv4. With this release, outgoing IPv6 messages are
correctly sent from the interface specified by clientaddr. (BZ#1190679)

  * The Net-SNMP daemon, snmpd, did not properly clean memory when reloading
its configuration file with multiple 'exec' entries. Consequently, the
daemon terminated unexpectedly. Now, the memory is properly cleaned, and
snmpd no longer crashes on reload. (BZ#1228893)

  * Prior to this update, snmpd did not parse complete IPv4 traffic
statistics, but reported the number of received or sent bytes in the
IP-MIB::ipSystemStatsTable only for IPv6 packets and not for IPv4.
This affected objects ipSystemStatsInOctets, ipSystemStatsOutOctets,
ipSystemStatsInMcastOctets, and ipSystemStatsOutMcastOctets. Now, the
statistics reported by snmpd are collected for IPv4 as well. (BZ#1235697)

  * The Net-SNMP daemon, snmpd, did not correctly detect the file system
change from read-only to read-write. Consequently, after remounting the
file system into the read-write mode, the daemon reported it to be still
in the read-only mode. A patch has been applied, and snmpd now detects the
mode changes as expected. (BZ#1241897)

All net-snmp users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"net-snmp on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00039.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-agent-libs", rpm:"net-snmp-agent-libs~5.7.2~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.2~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.7.2~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.7.2~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.7.2~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

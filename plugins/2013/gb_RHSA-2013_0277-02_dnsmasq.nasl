###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for dnsmasq RHSA-2013:0277-02
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00041.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870909");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:00:39 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-3411");
  script_bugtraq_id(54353);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for dnsmasq RHSA-2013:0277-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"dnsmasq on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The dnsmasq packages contain Dnsmasq, a lightweight DNS (Domain Name
  Server) forwarder and DHCP (Dynamic Host Configuration Protocol) server.

  It was discovered that dnsmasq, when used in combination with certain
  libvirtd configurations, could incorrectly process network packets from
  network interfaces that were intended to be prohibited. A remote,
  unauthenticated attacker could exploit this flaw to cause a denial of
  service via DNS amplification attacks. (CVE-2012-3411)

  In order to fully address this issue, libvirt package users are advised to
  install updated libvirt packages. Refer to RHSA-2013:0276 for additional
  information.

  This update also fixes the following bug:

  * Due to a regression, the lease change script was disabled. Consequently,
  the dhcp-script option in the /etc/dnsmasq.conf configuration file did
  not work. This update corrects the problem and the dhcp-script option now
  works as expected. (BZ#815819)

  This update also adds the following enhancements:

  * Prior to this update, dnsmasq did not validate that the tftp directory
  given actually existed and was a directory. Consequently, configuration
  errors were not immediately reported on startup. This update improves the
  code to validate the tftp root directory option. As a result, fault finding
  is simplified especially when dnsmasq is called by external processes such
  as libvirt. (BZ#824214)

  * The dnsmasq init script used an incorrect Process Identifier (PID) in the
  stop, restart, and condrestart commands. Consequently, if there were
  some dnsmasq instances running besides the system one started by the init
  script, then repeated calling of service dnsmasq with stop or restart
  would kill all running dnsmasq instances, including ones not started with
  the init script. The dnsmasq init script code has been corrected to obtain
  the correct PID when calling the stop, restart, and condrestart
  commands. As a result, if there are dnsmasq instances running in addition
  to the system one started by the init script, then by calling service
  dnsmasq with stop or restart only the system one is stopped or
  restarted. (BZ#850944)

  * When two or more dnsmasq processes were running with DHCP enabled on one
  interface, DHCP RELEASE packets were sometimes lost. Consequently, when two
  or  ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.48~13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dnsmasq-debuginfo", rpm:"dnsmasq-debuginfo~2.48~13.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

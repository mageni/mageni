###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for NetworkManager RHSA-2015:2315-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871481");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:19:55 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-0272", "CVE-2015-2924");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for NetworkManager RHSA-2015:2315-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"NetworkManager is a system network service
that manages network devices and connections.

It was discovered that NetworkManager would set device MTUs based on MTU
values received in IPv6 RAs (Router Advertisements), without sanity
checking the MTU value first. A remote attacker could exploit this flaw to
create a denial of service attack, by sending a specially crafted IPv6 RA
packet to disturb IPv6 communication. (CVE-2015-0272)

A flaw was found in the way NetworkManager handled router advertisements.
An unprivileged user on a local network could use IPv6 Neighbor Discovery
ICMP to broadcast a non-route with a low hop limit, causing machines to
lower the hop limit on existing IPv6 routes. If this limit is small enough,
IPv6 packets would be dropped before reaching the final destination.
(CVE-2015-2924)

The network-manager-applet and NetworkManager-libreswan packages have been
upgraded to upstream versions 1.0.6, and provide a number of bug fixes and
enhancements over the previous versions. (BZ#1177582, BZ#1243057)

Bugs:

  * It was not previously possible to set the Wi-Fi band to the 'a' or 'bg'
values to lock to a specific frequency band. NetworkManager has been fixed,
and it now sets the wpa_supplicant's 'freq_list' option correctly, which
enables proper Wi-Fi band locking. (BZ#1254461)

  * NetworkManager immediately failed activation of devices that did not have
a carrier early in the boot process. The legacy network.service then
reported activation failure. Now, NetworkManager has a grace period during
which it waits for the carrier to appear. Devices that have a carrier down
for a short time on system startup no longer cause the legacy
network.service to fail. (BZ#1079353)

  * NetworkManager brought down a team device if the teamd service managing
it exited unexpectedly, and the team device was deactivated. Now,
NetworkManager respawns the teamd instances that disappear and is able to
recover from a teamd failure avoiding disruption of the team device
operation. (BZ#1145988)

  * NetworkManager did not send the FQDN DHCP option even if host name was
set to FQDN. Consequently, Dynamic DNS (DDNS) setups failed to update the
DNS records for clients running NetworkManager. Now, NetworkManager sends
the FQDN option with DHCP requests, and the DHCP server is able to create
DNS records for such clients. (BZ#1212597)

  * The command-line client was not validating the vlan.flags property
correctly, and a spurious warning message was displayed when the nmcli tool
worked with VLAN connections. The validation routine has been fixed, and
the warning message no longer app ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"NetworkManager on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00038.html");
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

  if ((res = isrpmvuln(pkg:"ModemManager", rpm:"ModemManager~1.1.0~8.git20130913.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ModemManager-debuginfo", rpm:"ModemManager-debuginfo~1.1.0~8.git20130913.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ModemManager-glib", rpm:"ModemManager-glib~1.1.0~8.git20130913.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-debuginfo", rpm:"NetworkManager-debuginfo~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan", rpm:"NetworkManager-libreswan~1.0.6~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-debuginfo", rpm:"NetworkManager-libreswan-debuginfo~1.0.6~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-gnome", rpm:"NetworkManager-libreswan-gnome~1.0.6~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.0.6~27.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnm-gtk", rpm:"libnm-gtk~1.0.6~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"network-manager-applet-debuginfo", rpm:"network-manager-applet-debuginfo~1.0.6~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nm-connection-editor", rpm:"nm-connection-editor~1.0.6~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

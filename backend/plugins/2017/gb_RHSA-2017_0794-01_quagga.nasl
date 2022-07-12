###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for quagga RHSA-2017:0794-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871784");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-22 05:48:36 +0100 (Wed, 22 Mar 2017)");
  script_cve_id("CVE-2013-2236", "CVE-2016-1245", "CVE-2016-2342", "CVE-2016-4049", "CVE-2017-5495");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for quagga RHSA-2017:0794-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The quagga packages contain Quagga, the
free network-routing software suite that manages TCP/IP based protocols. Quagga
supports the BGP4, BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng protocols, and
is intended to be used as a Route Server and Route Reflector.

Security Fix(es):

  * A stack-based buffer overflow flaw was found in the way Quagga handled
IPv6 router advertisement messages. A remote attacker could use this flaw
to crash the zebra daemon resulting in denial of service. (CVE-2016-1245)

  * A stack-based buffer overflow flaw was found in the way the Quagga BGP
routing daemon (bgpd) handled Labeled-VPN SAFI routes data. A remote
attacker could use this flaw to crash the bgpd daemon resulting in denial
of service. (CVE-2016-2342)

  * A denial of service flaw was found in the Quagga BGP routing daemon
(bgpd). Under certain circumstances, a remote attacker could send a crafted
packet to crash the bgpd daemon resulting in denial of service.
(CVE-2016-4049)

  * A denial of service flaw affecting various daemons in Quagga was found. A
remote attacker could use this flaw to cause the various Quagga daemons,
which expose their telnet interface, to crash. (CVE-2017-5495)

  * A stack-based buffer overflow flaw was found in the way the Quagga OSPFD
daemon handled LSA (link-state advertisement) packets. A remote attacker
could use this flaw to crash the ospfd daemon resulting in denial of
service. (CVE-2013-2236)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section.");
  script_tag(name:"affected", value:"quagga on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-March/msg00054.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.15~14.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~0.99.15~14.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

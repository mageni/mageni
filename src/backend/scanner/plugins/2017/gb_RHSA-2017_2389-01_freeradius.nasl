###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2389-01_freeradius.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for freeradius RHSA-2017:2389-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871859");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:50 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-10978", "CVE-2017-10983", "CVE-2017-10984",
                "CVE-2017-10985", "CVE-2017-10986", "CVE-2017-10987");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for freeradius RHSA-2017:2389-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"FreeRADIUS is a high-performance and highly
  configurable free Remote Authentication Dial In User Service (RADIUS) server,
  designed to allow centralized authentication and authorization for a network.
  Security Fix(es): * An out-of-bounds write flaw was found in the way FreeRADIUS
  server handled certain attributes in request packets. A remote attacker could
  use this flaw to crash the FreeRADIUS server or to execute arbitrary code in the
  context of the FreeRADIUS server process by sending a specially crafted request
  packet. (CVE-2017-10984) * An out-of-bounds read and write flaw was found in the
  way FreeRADIUS server handled RADIUS packets. A remote attacker could use this
  flaw to crash the FreeRADIUS server by sending a specially crafted RADIUS
  packet. (CVE-2017-10978) * An out-of-bounds read flaw was found in the way
  FreeRADIUS server handled decoding of DHCP packets. A remote attacker could use
  this flaw to crash the FreeRADIUS server by sending a specially crafted DHCP
  request. (CVE-2017-10983) * A denial of service flaw was found in the way
  FreeRADIUS server handled certain attributes in request packets. A remote
  attacker could use this flaw to cause the FreeRADIUS server to enter an infinite
  loop, consume increasing amounts of memory resources, and ultimately crash by
  sending a specially crafted request packet. (CVE-2017-10985) * Multiple
  out-of-bounds read flaws were found in the way FreeRADIUS server handled
  decoding of DHCP packets. A remote attacker could use these flaws to crash the
  FreeRADIUS server by sending a specially crafted DHCP request. (CVE-2017-10986,
  CVE-2017-10987) Red Hat would like to thank the FreeRADIUS project for reporting
  these issues. Upstream acknowledges Guido Vranken as the original reporter of
  these issues.");
  script_tag(name:"affected", value:"freeradius on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00030.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~3.0.13~8.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-debuginfo", rpm:"freeradius-debuginfo~3.0.13~8.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

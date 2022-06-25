###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_cisco-sa-20170607-nxos.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco NX-OS Software Fibre Channel over Ethernet Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106858");
  script_cve_id("CVE-2017-6655");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco NX-OS Software Fibre Channel over Ethernet Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-nxos");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Fibre Channel over Ethernet (FCoE) protocol
implementation in Cisco NX-OS Software could allow an unauthenticated, adjacent attacker to cause a denial of
service (DoS) condition when an FCoE-related process unexpectedly reloads.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper FCoE frame padding validation.
An attacker could exploit this vulnerability by sending a stream of crafted FCoE frames to the targeted device.
The attacker's server must be directly connected to the FCoE interface on the device that is running Cisco
NX-OS Software to exploit this vulnerability.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a DoS condition, which would
impact FCoE traffic passing through the device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-08 12:12:26 +0700 (Thu, 08 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

device = get_kb_item("cisco_nx_os/device");
if (!device)
  exit(0);

model = get_kb_item("cisco_nx_os/model");
if (!model)
  exit(0);

if (device == "Nexus") {
  if (model =~ "^(5|7)[0-9]+") {
    affected = make_list('8.0(1)S2',
                         '8.3(0)CV(0.833)',
                         '7.3(1)N1(1)',
                         '8.0(1)(ED)');

    foreach af (affected) {
      if (version = af) {
        report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
  exit(99);
}

if (device == "MDS") {
  if (model =~ "^9[0-9]+") {
    if (version == "7.3(1)D1(1)") {
      report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);


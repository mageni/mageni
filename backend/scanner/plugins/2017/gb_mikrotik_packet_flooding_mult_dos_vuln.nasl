###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_packet_flooding_mult_dos_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# MikroTik RouterOS Packet Flooding Multiple Denial-of-Service Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811066");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-7285", "CVE-2017-8338");
  script_bugtraq_id(97266);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-02 15:14:27 +0530 (Fri, 02 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("MikroTik RouterOS Packet Flooding Multiple Denial-of-Service Vulnerabilities");

  script_tag(name:"summary", value:"This host is running MikroTik router
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors in the
  network stack of MikroTik exhausting all available CPU via a flood of TCP
  RST packets and UDP packets.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition on the MikroTik router.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions 6.38.5");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41752");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017030242");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017050062");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/May/59");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version == "6.38.5") {
  report = report_fixed_ver( installed_version:version, fixed_version:"None" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

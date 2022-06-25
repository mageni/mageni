###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_52027.nasl 12131 2018-10-26 14:03:52Z mmartin $
#
# Multiple Cisco Nexus Devices IP Stack Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103801");
  script_bugtraq_id(52027);
  script_cve_id("CVE-2012-0352");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12131 $");

  script_name("Multiple Cisco Nexus Devices IP Stack Remote Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52027");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/ps9902/tsd_products_support_series_home.html");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/ps9670/");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120215-nxos");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 16:03:52 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-10 11:38:56 +0200 (Thu, 10 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the device to crash,
denying service to legitimate users.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cisco NX-OS 4.2.x before 4.2(1)SV1(5.1) on Nexus 1000v series
switches. Version 4.x and 5.0.x before 5.0(2)N1(1) on Nexus 5000 series switches, and
4.2.x before 4.2.8, 5.0.x before 5.0.5, and 5.1.x before 5.1.1 on Nexus 7000
series switches allows remote attackers to cause a denial of service
(netstack process crash and device reload) via a malformed IP packet, aka Bug
IDs CSCti23447, CSCti49507, and CSCtj01991.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the referenced advisory
for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Multiple Cisco Nexus devices are prone to a denial-of-service
vulnerability.");

  script_tag(name:"affected", value:"The following devices are affected:

Cisco Nexus 1000V

Cisco Nexus 5000

Cisco Nexus 7000");

  exit(0);
}

include("host_details.inc");

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if(!nx_model = get_kb_item("cisco_nx_os/model"))exit(0);
if(!nx_ver = get_kb_item("cisco_nx_os/version"))exit(0);

affected = FALSE;

if('1000V' >< nx_model) {

  affected = make_list(
                       "4.2(1)sv1(4a)",
                       "4.2(1)sv1(4)",
                       "4.0(4)sv1(1)",
                       "4.0(4)sv1(2)",
                       "4.0(4)sv1(3)",
                       "4.0(4)sv1(3a)",
                       "4.0(4)sv1(3b)",
                       "4.0(4)sv1(3c)",
                       "4.0(4)sv1(3d)",
                       "4.2(1)n2(1a)",
                       "4.1(3)n1(1a)",
                       "4.1(3)n1(1)",
                       "4.0(1a)n2(1a)",
                       "4.0(1a)n2(1)",
                       "4.0(1a)n1(1a)",
                       "4.0(1a)n1(1)",
                       "4.0(0)n1(2a)",
                       "4.0(0)n1(1a)",
                       "4.0(0)n1(2)",
                       "4.2(1)n2(1)",
                       "4.2(1)n1(1)",
                       "4.1(3)n2(1a)",
                       "4.1(3)n2(1)");
}

else if (nx_model =~ '^5') {

  affected = make_list(
                       "5.1(3)n1(1a)",
                       "5.0(3)n2(2b)",
                       "5.0(3)n2(2a)",
                       "5.0(3)n2(2)",
                       "5.0(3)n2(1)",
                       "5.0(3)n1(1c)",
                       "5.1(3)n1(1)",
                       "5.0(2)n2(1a)",
                       "5.0(2)n2(1)",
                       "5.0(3)n1(1b)",
                       "5.0(3)n1(1a)",
                       "5.0(3)n1(1)");

}

else if ( nx_model =~ "^7" ) {

  affected = make_list(
                       "5.0(3)n1(1)",
                       "4.2(6)",
                       "4.2(3)",
                       "4.2(4)",
                       "4.2.(2a)",
                       "5.0(3)",
                       "5.0(2a)",
                       "4.2(1)",
                       "4.2(2)",
                       "5.0(2)",
                       "5.1(2)",
                       "4.1.(2)",
                       "4.1.(3)",
                       "4.1.(4)",
                       "4.1.(5)",
                       "5.1(6)",
                       "5.1(1a)",
                       "5.1(3)",
                       "5.1(4)",
                       "5.1(5)");

}

if(affected) {

  foreach affected_nx_ver (affected) {
    if(nx_ver == affected_nx_ver) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

}

exit(99);

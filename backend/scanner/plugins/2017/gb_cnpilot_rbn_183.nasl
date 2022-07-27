###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cnpilot_rbn_183.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# cnPilot R200/201 RSA Keys Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = "cpe:/o:cambium_networks:cnpilot_series_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140187");
  script_version("$Revision: 12106 $");
  script_cve_id("CVE-2017-5859");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 17:34:31 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("cnPilot R200/201 RSA Keys Vulnerability");

  script_tag(name:"summary", value:"On Cambium Networks cnPilot R200/201 devices before 4.3, there is a vulnerability involving the certificate of the device and its RSA keys, aka RBN-183.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"cnPilot R200/201 devices before 4.3");

  script_tag(name:"solution", value:"Update to 4.3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.cambiumnetworks.com/file/3f88842a39f37b0d4ce5d43e5aa21bf1c4f9f1ca");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_cnpilot_snmp_detect.nasl");
  script_mandatory_keys("cnPilot/model", "cnPilot/version");
  script_require_udp_ports("Services/udp/snmp", 161);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );
if( ! model = get_kb_item( "cnPilot/model" ) ) exit( 0 );

if( model !~ '^R20(0|1)' ) exit( 0 );

if( "-" >< version )
{
  v = split( version, sep:"-", keep:FALSE );
  if( ! isnull( v[0] ) )
    version = v[0];
}

if( version_is_less( version:version, test_version:"4.3" ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:"4.3" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


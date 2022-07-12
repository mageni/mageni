###############################################################################
# OpenVAS Vulnerability Test
# $Id: ipswitch_IMail_38109.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Ipswitch IMail Server Multiple Local Privilege Escalation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:ipswitch:imail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100490");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
  script_bugtraq_id(38109);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ipswitch IMail Server Multiple Local Privilege Escalation Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_ipswitch_imail_server_detect.nasl");
  script_mandatory_keys("Ipswitch/IMail/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38109");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-02/0076.html");
  script_xref(name:"URL", value:"http://www.ipswitch.com/Products/IMail_Server/index.html");

  script_tag(name:"impact", value:"Local attackers may exploit these issues to gain elevated privileges,
  which may lead to a complete compromise of an affected computer.");

  script_tag(name:"affected", value:"IMail Server 11.01 is affected. Other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
  information.");

  script_tag(name:"summary", value:"Ipswitch IMail Server is prone to multiple local privilege-escalation
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit(0);

if( version_is_equal( version:version, test_version:"11.01" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
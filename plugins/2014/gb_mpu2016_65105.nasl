###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mpu2016_65105.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Emerson Network Power Avocent MergePoint Unity 2016 KVM Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103894");
  script_version("$Revision: 12021 $");
  script_bugtraq_id(65105);
  script_cve_id("CVE-2013-6030");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-27 19:06:00 +0100 (Mon, 27 Jan 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Emerson Network Power Avocent MergePoint Unity 2016 KVM Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_mpu2016_detect.nasl", "gb_mpu2016_snmp_detect.nasl");
  script_mandatory_keys("MPU2016/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65105");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to obtain sensitive
  information that could aid in further attacks.");
  script_tag(name:"vuldetect", value:"Check the firmware version.");
  script_tag(name:"insight", value:"Directory traversal vulnerability on the Emerson
  Network Power Avocent MergePoint Unity 2016 (aka MPU2016) KVM switch
  with firmware 1.9.16473 allows remote attackers to read arbitrary
  files via unspecified vectors, as demonstrated by reading the
  /etc/passwd file.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"summary", value:"Emerson Network Power Avocent MergePoint Unity 2016 KVM is prone to a
  directory-traversal vulnerability because it fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"affected", value:"Emerson Network Power Avocent MergePoint Unity 2016 KVM firmware
  1.9.16473 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.9.16473" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

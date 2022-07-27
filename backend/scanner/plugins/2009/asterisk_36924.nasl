###############################################################################
# OpenVAS Vulnerability Test
# $Id: asterisk_36924.nasl 4887 2016-12-30 12:54:28Z cfi $
#
# Asterisk SIP Response Username Enumeration Remote Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:digium:asterisk';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100341");
  script_version("$Revision: 4887 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-30 13:54:28 +0100 (Fri, 30 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-11-10 12:45:58 +0100 (Tue, 10 Nov 2009)");
  script_bugtraq_id(36924);
  script_cve_id("CVE-2009-3727");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Asterisk SIP Response Username Enumeration Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Ver", "Asterisk-PBX/Installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36924");
  script_xref(name:"URL", value:"http://www.asterisk.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507688");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-008.html");

  script_tag(name:"solution", value:"The vendor has released an advisory and updates. Please see the
  references for details.");

  script_tag(name:"summary", value:"Asterisk is prone to an information-disclosure vulnerability because
  it doesn't provide safe responses to failed authentication attempts.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to discover whether specific
  usernames exist. Information harvested may aid in launching further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range( version:version, test_version:"1.6.1", test_version2:"1.6.1.8" ) ||
    version_in_range( version:version, test_version:"1.6", test_version2:"1.6.16" ) ||
    version_in_range( version:version, test_version:"1.4.26", test_version2:"1.4.26.2" ) ||
    version_in_range( version:version, test_version:"1.2", test_version2:"1.2.34" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );
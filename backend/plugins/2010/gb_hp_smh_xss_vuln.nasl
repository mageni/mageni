##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# HP System Management Homepage Cross site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800293");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(38081);
  script_cve_id("CVE-2009-4185");
  script_name("HP System Management Homepage Cross-site scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=126529736830358&w=2");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509195/100/0/threaded");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02000727");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'proxy/smhui/getuiinfo'
  script when processing the 'servercert' parameter.");
  script_tag(name:"solution", value:"Upgrade to HP SMH version 6.0.0.96(for windows), 6.0.0-95(for linux) or later.");
  script_tag(name:"summary", value:"This host is running  HP System Management Homepage (SMH) and is
  prone to Cross site scripting vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  script on the user's web browser by injecting web script and steal cookie
  based authentication credentials.");
  script_tag(name:"affected", value:"HP System Management Homepage (SMH) versions prior to 6.0 on all platforms.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:"6.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
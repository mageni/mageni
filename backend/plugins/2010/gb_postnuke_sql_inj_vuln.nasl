##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postnuke_sql_inj_vuln.nasl 14168 2019-03-14 08:10:09Z cfischer $
#
# PostNuke modload Module 'sid' Parameter SQL Injection Vulnerability
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

CPE = "cpe:/a:postnuke:postnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800771");
  script_version("$Revision: 14168 $");
  script_cve_id("CVE-2010-1713");
  script_bugtraq_id(39713);
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PostNuke modload Module 'sid' Parameter SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_mandatory_keys("postnuke/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58204");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12410");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39713");

  script_tag(name:"insight", value:"The flaw exists due to failure to sufficiently sanitize user
  supplied data to 'modules.php' via 'sid' parameter before using it in an SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running PostNuke and is prone SQL injection vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access,
  modify or delete information in the underlying database.");

  script_tag(name:"affected", value:"PostNuke version 0.764");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit( 0 );

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_equal( version:vers, test_version:"0.76" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
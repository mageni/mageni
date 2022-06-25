###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sugarcrm_xxe_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# SugarCRM 6.5.16 XXE Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113111");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-14 10:40:00 +0100 (Wed, 14 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3244");
  script_bugtraq_id(68102);

  script_name("SugarCRM 6.5.16 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_tag(name:"summary", value:"SugarCRM is prone to an XML external entity vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists within the RSSDashlet dashlet.");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to read arbitrary files or potentially execute arbitrary code via a crafted DTD in an XML request.");
  script_tag(name:"affected", value:"SugarCRM through version 6.5.16.");
  script_tag(name:"solution", value:"Update to version 6.5.17.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/92");
  script_xref(name:"URL", value:"https://web.archive.org/web/20151105182132/http://www.pnigos.com/?p=294");

  exit(0);
}

CPE = "cpe:/a:sugarcrm:sugarcrm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "6.5.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.17" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pkp_open_journal_systems_xss_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# PKP Open Journal Systems 3.X XSS Vulnerability
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107322");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-14 10:29:01 +0200 (Thu, 14 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-12229");

  script_name("PKP Open Journal Systems 3.X XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pkp_open_journal_systems_detect.nasl");
  script_mandatory_keys("pkp/open_journal_systems/version");

  script_tag(name:"summary", value:"PKP Open Journal Systems is prone to a cross-site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A cross-site scripting (XSS) vulnerability in Public Knowledge Project (PKP)
  Open Journal System (OJS) allows remote attackers to inject arbitrary web script or
  HTML via the templates/frontend/pages/search.tpl $authors parameter (aka the By Author field).");
  script_tag(name:"affected", value:"Open Journal Systems version before 3.1.1-2.");
  script_tag(name:"solution", value:"Upgrade to Open Journal Systems version 3.1.1-2 or later.");

  script_xref(name:"URL", value:"https://metamorfosec.com/Files/Advisories/METS-2018-001_A%20XSS%20Vulnerability%20in%20OJS%203.X.txt");
  script_xref(name:"URL", value:"https://github.com/pkp/pkp-lib/issues/3785");

  exit(0);
}

CPE = "cpe:/a:pkp:open_journal_systems";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.1.1-2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.1-2" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

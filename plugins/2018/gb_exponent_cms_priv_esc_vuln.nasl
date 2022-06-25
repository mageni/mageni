###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponent_cms_priv_esc_vuln.nasl 9150 2018-03-20 12:57:43Z jschulte $
#
# Exponent CMS 2.4.1 Patch 5 - Privilege Escalation Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113140");
  script_version("$Revision: 9150 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-20 13:57:43 +0100 (Tue, 20 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-20 13:55:55 +0100 (Tue, 20 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-18213");

  script_name("Exponent CMS 2.4.1 Patch 5 - Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_mandatory_keys("ExponentCMS/installed");

  script_tag(name:"summary", value:"Exponent CMS allows rogue admins to elevate their privileges.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Exponent CMS version 2.0.0 through 2.4.1 Patch 5.");
  script_tag(name:"solution", value:"Update to 2.4.1 Patch 6.");

  script_xref(name:"URL", value:"http://www.exponentcms.org/news/patch-6-released-for-v2-4-1-to-fix-a-few-big-issues");
  script_xref(name:"URL", value:"https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.1patch6");

  exit( 0 );
}

CPE = "cpe:/a:exponentcms:exponent_cms";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.4.1.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.1.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

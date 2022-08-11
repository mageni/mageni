###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_email_gateway_sb10091.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# McAfee Email Gateway - Three SSLv3 Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:mcafee:email_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105157");
  script_cve_id("CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3568");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11872 $");

  script_name("McAfee Email Gateway - Three SSLv3 Vulnerabilities");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10091");

  script_tag(name:"vuldetect", value:"Check the installed version and hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"McAfee Email Gateway is vulnerable to one or more of the three Open Secure
Sockets Layer (OpenSSL) 3.0 (SSLv3) vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-07 17:42:14 +0100 (Wed, 07 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_email_gateway_version.nasl");
  script_mandatory_keys("mcafee_email_gateway/product_version", "mcafee_email_gateway/patches");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

product = get_kb_item("mcafee_email_gateway/product_name");
if( ! product ) product = 'McAfee Email Gateway';

if( ! patches = get_kb_item("mcafee_email_gateway/patches") ) exit( 0 );

if( version =~ "^7\.0\." )
{
  fixed = '7.0.2934.114';
  patch = '7.0.5h1014812';
}

else if (version =~ "^7\.5\.")
{
  fixed = "7.5.3088.113";
  patch = "7.5.4h1014806";
}

else if (version =~ "^7\.6\.")
{
  fixed = "7.6.3044.120";
  patch = "7.6.2h1014803";
}

else
 exit( 0 );

if( patch >< patches ) exit( 99 );

if( version_is_less( version:version, test_version:fixed ) )
{
  report = product + ' (' + version + ') is missing the patch ' + patch + '.\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );


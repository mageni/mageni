###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_info_disclosure_vuln.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# Drupal Information Disclosure Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800909");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2374");
  script_bugtraq_id(35548);
  script_name("Drupal Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://drupal.org/node/507572");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35657");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jul/1022497.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl");
  script_mandatory_keys("drupal/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain that set of credentials which
  are included in the generated links.");

  script_tag(name:"affected", value:"Drupal Version 5.x before 5.19 and 6.x before 6.13 on all platforms.");

  script_tag(name:"insight", value:"Application fails to sanitize login attempts for pages that contain a sortable
  table, which includes the username and password in links that can be read from
  the HTTP referer header of external web sites that are visited from those links
  or when page caching is enabled, the Drupal page cache.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Drupal 5.19 or 6.13 or later.");

  script_tag(name:"summary", value:"The host is installed with Drupal and is prone to Information
  Disclosure vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!drPort = get_app_port( cpe:CPE ))
  exit(0);

if( ! drupalVer = get_app_version( cpe:CPE, port:drPort, version_regex:"^[0-9]\.[0-9]+") )
  exit( 0 );

if(version_in_range(version:drupalVer, test_version:"5.0", test_version2:"5.18") ||
   version_in_range(version:drupalVer, test_version:"6.0", test_version2:"6.12")){
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"5.19/6.13");
  security_message(port:drPort, data:report);
  exit(0);
}

exit(99);
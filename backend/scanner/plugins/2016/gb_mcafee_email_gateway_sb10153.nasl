###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_email_gateway_sb10153.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# McAfee Email Gateway - Cross-Site Scripting (XSS) Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105599");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12051 $");

  script_name("McAfee Email Gateway - Cross-Site Scripting (XSS) Vulnerability");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10153");

  script_tag(name:"vuldetect", value:"Check the installed version and hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"McAfee Email Gateway is vulnerable to cross-site scripting (XSS) in the generation of HTML email alerts using SMTP.");
  script_tag(name:"insight", value:"This issue is encountered when File Filtering is enabled with the action set to ESERVICES:REPLACE. With this configuration, when an email with an attachment is blocked and replaced with an alert, the corresponding alert displays the email attachment `as is` without it being XML/HTML escaped.");
  script_tag(name:"affected", value:"Email Gateway 7.6 < 7.6.404");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-08 11:17:54 +0200 (Fri, 08 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
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

if (version =~ "^7\.6\.")
  patch = "7.6.404-3328.101";
else
 exit( 99 );

if( patch >< patches ) exit( 99 );

report = product + ' (' + version + ') is missing the patch ' + patch + '.\n';
security_message( port:0, data:report );
exit( 0 );


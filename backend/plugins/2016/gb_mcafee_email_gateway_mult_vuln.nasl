###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_email_gateway_mult_vuln.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# McAfee Email Gateway Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.807868");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2013-7103", "CVE-2013-7104", "CVE-2013-7092");
  script_bugtraq_id(64150);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-14 11:01:01 +0530 (Thu, 14 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("McAfee Email Gateway Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running McAfee Email Gateway
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Insufficient validation of input via shell metacharacters in the value
    attribute in a 'TestFile XML', 'hostname', 'Command' and 'Script
    XML' element.

  - Insufficient validation of commands via the 'events_col', 'event_id',
    'reason', 'events_order', 'emailstatus_order', 'emailstatus_col' JSON keys");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote authenticated attackers to run arbitrary shell commands.");

  script_tag(name:"affected", value:"McAfee Email Gateway (MEG) versions 7.0,
  7.5 and 7.6");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/bulletins/SB13-357");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_email_gateway_version.nasl");
  script_mandatory_keys("mcafee_email_gateway/product_version", "mcafee_email_gateway/patches");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE)) exit(0);

product = get_kb_item("mcafee_email_gateway/product_name");
if(!product) product = 'McAfee Email Gateway';

if(! patches = get_kb_item("mcafee_email_gateway/patches")) exit(0);

if (version =~ "^7\.5\.")
{
  patch = "7.5h952384";
  fix = '7.5.2846.113';
}

##Fixed version information not available for MEG 7.0 and 7.6
##Covering only 7.5

if(patch >< patches) exit(99);

if(version_is_less(version:version, test_version:fix))
{
  report = product + ' (' + version + ') is missing the patch ' + patch + ' (' + fix + ').\n';
  security_message(port:0, data:report);
  exit(0);
}

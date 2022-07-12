##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_mult_vuln_apr11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HP System Management Homepage Multiple Vulnerabilities
#
# Authors:
# Antu  Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902413");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-1540", "CVE-2011-1541");
  script_bugtraq_id(47507, 47512);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HP System Management Homepage Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100629/HPSBMA02662-SSRT100409.txt");

  script_tag(name:"insight", value:"The flaw is caused by unspecified errors with unknown attack vectors.");
  script_tag(name:"solution", value:"Apply patch or upgrade to HP SMH version 6.3 or later, *****
  NOTE: Ignore this warning if patch is applied already.
  *****");
  script_tag(name:"summary", value:"This host is running  HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system and also cause Denial of Service (DoS).");
  script_tag(name:"affected", value:"HP System Management Homepage (SMH) prior to 6.3");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.hp.com/servers/manage/smh");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:"6.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.3");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
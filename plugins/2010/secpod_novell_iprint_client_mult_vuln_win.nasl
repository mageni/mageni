###############################################################################
# OpenVAS Vulnerability Test
#
# Novell iPrint Client Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902098");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)");
  script_cve_id("CVE-2010-3105", "CVE-2010-1527");
  script_bugtraq_id(42576);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell iPrint Client Multiple Vulnerabilities (windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40805");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61220");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-104/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7006679");

  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code, to
  cause buffer overflow or cause the application to crash.");

  script_tag(name:"affected", value:"Novell iPrint Client version prior to 5.44 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'PluginGetDriverFile' function, which interprets an uninitialized
  memory location as a pointer value.

  - An improper bounds checking by the 'call-back-url' parameter for a
  'op-client-interface-version' operation. A remote attacker can use an overly
  long call-back-url parameter to overflow a buffer and execute arbitrary code on the system.");

  script_tag(name:"solution", value:"Upgrade to Novell iPrint Client version 5.44 or later.");

  script_tag(name:"summary", value:"The host is installed with Novell iPrint Client and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"5.44" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.44", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_konqueror_kde_dos_vuln.nasl 12712 2018-12-08 09:12:52Z cfischer $
#
# Konqueror in KDE Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:kde:konqueror";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900417");
  script_version("$Revision: 12712 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-08 10:12:52 +0100 (Sat, 08 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-4514", "CVE-2008-5712");
  script_bugtraq_id(31696);
  script_name("Konqueror in KDE Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_kde_konqueror_detect.nasl");
  script_mandatory_keys("KDE/Konqueror/Ver");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/6704");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32208");

  script_tag(name:"summary", value:"This host is running Konqueror and is prone to Denial of Service
  Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to trigger the use of a deleted
  object within the HTMLTokenizer::scriptHandler() method and can cause a crash.");

  script_tag(name:"affected", value:"Konqueror in KDE version 3.5.9 or prior.");

  script_tag(name:"insight", value:"These flaws are due to,

  - improper handling of JavaScript document.load Function calls targeting
    the current document which can cause denial of service.

  - HTML parser in KDE Konqueror causes denial of service via a long attribute
    in HR element or a long BGCOLOR or BORDERCOLOR.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:FALSE ) )
  exit( 0 );

ver = infos['version'];
loc = infos['location'];

if( version_is_less_equal( version:ver, test_version:"3.5.10" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"WillNotFix", install_path:loc );
  security_message( port:0, data:report );
}

exit( 0 );
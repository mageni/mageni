##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_mult_vuln.nasl 13957 2019-03-01 09:46:54Z ckuersteiner $
#
# OpenCart Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

CPE = 'cpe:/a:opencart:opencart';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802751");
  script_version("$Revision: 13957 $");
  script_bugtraq_id(52957);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 10:46:54 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-18 18:47:56 +0530 (Wed, 18 Apr 2012)");

  script_name("OpenCart Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48762");
  script_xref(name:"URL", value:"http://www.waraxe.us/advisory-84.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522240");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenCart/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload PHP scripts
and include arbitrary files from local resources via directory traversal attacks.");

  script_tag(name:"affected", value:"OpenCart version 1.5.2.1 and prior");

  script_tag(name:"insight", value:"The flaws are due to

  - An input passed via the 'route' parameter to index.php is not properly verified before being used to include
    files.

  - 'admin/controller/catalog/download.php' script does not properly validate uploaded files, which can be
    exploited to execute arbitrary PHP code by uploading a PHP file with an appended '.jpg' file extension.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"OpenCart is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?route=" + crap(data:"..%5C",length:3*15) + files[file] + "%00";

  if(http_vuln_check(port:port, url:url,pattern:file, check_header:TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port:port, data: report);
    exit(0);
  }
}

exit(99);

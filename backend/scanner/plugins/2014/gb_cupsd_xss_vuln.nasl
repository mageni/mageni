###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cupsd_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# CUPS Web Interface Cross Site Scripting Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802071");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2856");
  script_bugtraq_id(66788);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-22 13:16:12 +0530 (Tue, 22 Apr 2014)");
  script_name("CUPS Web Interface Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L4356");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57880/");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/04/14/2");

  script_tag(name:"summary", value:"This host is installed with CUPS and is prone to cross site scripting
  vulnerability");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to get
  domain or not.");

  script_tag(name:"insight", value:"Flaws is due to is_path_absolute()function does not validate input via URL
  path before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Common Unix Printing System(CUPS)version before 1.7.2");

  script_tag(name:"solution", value:"Upgrade to version 1.7.2, or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.cups.org/software.php");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!cups_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:cups_port)){
  exit(0);
}

url = dir + "<SCRIPT>alert(document.domain)</SCRIPT>.shtml";
req = http_get(item:url, port:cups_port);
res = http_send_recv(port:cups_port, data:req);

## Patched version reply with specific code/message
if("403 Forbidden" >!< res && "<SCRIPT>alert(document.domain)</SCRIPT>" >< res){
  report = report_vuln_url(port:cups_port, url:url);
  security_message(port:cups_port, data:report);
  exit(0);
}

exit(99);
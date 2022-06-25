##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_multiple_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Symantec Web Gateway Multiple Vulnerabilities-Aug2013
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803732");
  script_version("$Revision: 11865 $");
  script_bugtraq_id(61106, 61101, 61103, 61102, 61104);
  script_cve_id("CVE-2013-1616", "CVE-2013-1617", "CVE-2013-4670", "CVE-2013-4671",
                "CVE-2013-4672");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-06 15:41:47 +0530 (Tue, 06 Aug 2013)");
  script_name("Symantec Web Gateway Multiple Vulnerabilities-Aug2013");
  script_tag(name:"summary", value:"This host is running Symantec Web Gateway and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Get the installed version Symantec Web Gateway with the help detect NVT and
check the version is vulnerable or not.");
  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version 5.1.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Unspecified errors related to the SWG console interface, login prompt of the
  SWG console and sudo configuration.

  - Certain unspecified input is not properly sanitised before being returned to
  the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the request.");
  script_tag(name:"affected", value:"Symantec Web Gateway versions prior to 5.1.1");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain escalated privileges and
conduct cross-site scripting and cross-site request forgery attacks and
compromise a vulnerable system.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54294");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27136");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/177");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_mandatory_keys("symantec_web_gateway/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.symantec.com/business/web-gateway");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE);
if(!port){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if("unknown" >!< vers && vers)
{
  if(version_is_less(version:vers, test_version:"5.1.1"))
  {
    security_message(port);
    exit(0);
  }
}
